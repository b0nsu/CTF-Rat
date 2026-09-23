"""Optional local GDB/MI session. All observations are candidate artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

from . import analysis
from .artifact import put_bytes
from .run_manifest import read as read_run, sha256_file
from .runner import ResourceLimits, spawn_owned, terminate_owned
from .schema import validate

VERSION = "gdb-mi-session/1"
MAX_OBSERVATIONS = 64
_STARTED_WORKERS = {}
ID = re.compile(r"gdb_[0-9a-f]{32}\Z")
ADDR = re.compile(r"(?:0x[0-9a-fA-F]+|[0-9]+)\Z")
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_:.]*\Z")


class ConnectionLostError(RuntimeError):
    pass


def _digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _session_dir(binary):
    path = os.path.join(os.path.dirname(os.path.realpath(binary)), ".rat", "gdb-sessions")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _manifest(binary):
    binary = os.path.realpath(binary)
    path = os.path.join(os.path.dirname(binary), "run.json")
    run = read_run(path)
    if run["status"] != "active":
        raise ValueError("run is not active")
    digest = sha256_file(binary)
    if not any(x.get("role") == "binary" and x.get("sha256") == digest for x in run["inputs"]):
        raise ValueError("binary digest does not match active run")
    repo = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    guard_path = os.path.join(os.environ.get("CTF_HOME", repo), "ACTIVE.json")
    with open(guard_path, encoding="utf-8") as handle:
        guard = json.load(handle)
    if guard.get("chal") != run["challenge"].get("name"):
        raise ValueError("ctfguard active challenge does not match run")
    return run, digest


def _paths(binary, session_id):
    if not ID.fullmatch(session_id):
        raise ValueError("invalid session ID")
    base = _session_dir(binary)
    # macOS limits AF_UNIX path bytes to 104; challenge directories can be long.
    label = hashlib.sha256((os.path.realpath(binary) + session_id).encode()).hexdigest()[:32]
    return "/tmp/rat-gdb-" + label + ".sock", os.path.join(base, session_id + ".json")


def _exchange(path, request, timeout=6):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(path)
        connection.sendall(json.dumps(request, sort_keys=True).encode() + b"\n")
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = connection.recv(65536)
            if not chunk or len(data) + len(chunk) > 1024 * 1024:
                raise RuntimeError("session response missing or too large")
            data.extend(chunk)
        return json.loads(data)


def start(binary, scenario_path, *, total_timeout=120, idle_timeout=30, action_timeout=10, output_cap=8192):
    binary = os.path.realpath(binary)
    if not os.path.isfile(binary):
        raise ValueError("binary missing")
    if not shutil.which("gdb"):
        raise RuntimeError("GDB is not installed")
    run, binary_digest = _manifest(binary)
    sc = analysis.scenario(scenario_path)
    if not isinstance(sc.get("argv", []), list) or not all(isinstance(x, str) for x in sc.get("argv", [])):
        raise ValueError("scenario argv must be strings")
    if not isinstance(sc.get("env", {}), dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in sc.get("env", {}).items()):
        raise ValueError("scenario env must be string pairs")
    if sc.get("cwd") is not None and not os.path.isdir(sc["cwd"]):
        raise ValueError("scenario cwd missing")
    if analysis.scenario_stdin(sc):
        raise ValueError("interactive GDB session does not support scenario stdin")
    if (not 1 <= total_timeout <= 3600 or not 1 <= idle_timeout <= total_timeout
            or not 1 <= action_timeout <= total_timeout or not 256 <= output_cap <= 65536):
        raise ValueError("invalid timeout/output limits")
    session_id = "gdb_" + uuid.uuid4().hex
    sock, config_path = _paths(binary, session_id)
    config = {"session_id": session_id, "binary": binary, "binary_digest": binary_digest,
              "run_id": run["run_id"],
              "environment_digest": _digest({"run_environment": run["environment"],
                                              "scenario_env": sc.get("env", {}),
                                              "cwd": sc.get("cwd"), "argv": sc.get("argv", [])}),
              "scenario_digest": sha256_file(scenario_path), "scenario": sc,
              "total_timeout": total_timeout, "idle_timeout": idle_timeout,
              "action_timeout": action_timeout,
              "output_cap": output_cap, "socket": sock, "store": os.path.join(os.path.dirname(binary), ".rat")}
    with open(config_path, "x", encoding="utf-8") as handle:
        json.dump(config, handle, sort_keys=True)
    os.chmod(config_path, 0o600)
    worker = subprocess.Popen([sys.executable, "-m", "ratlib.gdb_session", "serve", config_path],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              env={**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(__file__))},
                              start_new_session=True)
    for _ in range(int((action_timeout + 2) * 20)):
        if os.path.exists(sock):
            try:
                result = _exchange(sock, {"action": "status", "run_id": run["run_id"]}, timeout=1)
                if result.get("status") == "ok":
                    worker.stderr.close()
                    _STARTED_WORKERS[session_id] = worker
                    return result
                raise RuntimeError(result.get("error", "session start failed"))
            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, FileNotFoundError, socket.timeout):
                pass
        if worker.poll() is not None:
            break
        time.sleep(0.05)
    try: os.unlink(config_path)
    except FileNotFoundError: pass
    stderr = worker.stderr.read(4096).decode(errors="replace").strip() if worker.poll() is not None else ""
    detail = stderr.splitlines()[-1] if stderr else ""
    worker.stderr.close()
    raise RuntimeError("GDB session did not start; worker exit=%s %s" % (worker.poll(), detail))


def request(binary, session_id, action, **params):
    binary = os.path.realpath(binary)
    sock, config_path = _paths(binary, session_id)
    if action == "close" and not os.path.exists(sock):
        worker = _STARTED_WORKERS.pop(session_id, None)
        if worker: worker.wait(timeout=2)
        return {"status": "closed", "session_id": session_id}
    run, digest = _manifest(binary)
    if not os.path.exists(sock):
        raise ConnectionLostError("session socket is gone; session closed or expired")
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    try:
        result = _exchange(sock, {"action": action, "run_id": run["run_id"],
                                  "binary_digest": digest, **params}, timeout=config["action_timeout"] + 5)
    except (ConnectionResetError, BrokenPipeError, FileNotFoundError, socket.timeout) as exc:
        raise ConnectionLostError("session connection lost") from exc
    if action == "close" or result.get("session_ended") or result.get("status") == "timeout":
        worker = _STARTED_WORKERS.pop(session_id, None)
        if worker: worker.wait(timeout=2)
    return result


class MI:
    def __init__(self, config):
        sc = config["scenario"]
        self.proc = spawn_owned(["gdb", "--nx", "--quiet", "--interpreter=mi2", "--args",
                                 config["binary"], *sc.get("argv", [])], cwd=sc.get("cwd"),
                                env=sc.get("env", {}), limits=ResourceLimits(cpu_seconds=int(config["total_timeout"] + 5)))
        self.lines = queue.Queue(maxsize=512)
        self.token = 0
        self.inferior_pid = None
        self.original_inferior_pid = None
        self.identity_changed = False
        self.exec_catchpoint = None
        self.binary = os.path.realpath(config["binary"])
        self.binary_digest = config["binary_digest"]
        self.output_cap = config["output_cap"]
        threading.Thread(target=self._read, args=(self.proc.stdout,), daemon=True).start()
        threading.Thread(target=self._read, args=(self.proc.stderr,), daemon=True).start()

    def _read(self, pipe):
        try:
            for line in iter(lambda: pipe.readline(65536), b""):
                self.lines.put(line.decode("utf-8", errors="replace").rstrip("\r\n"))
        finally:
            self.lines.put(None)

    def command(self, command, *, stop=False, timeout=10):
        self.token += 1
        token = str(self.token)
        self.proc.stdin.write((token + command + "\n").encode()); self.proc.stdin.flush()
        output, size, kept, truncated, result, stopped = [], 0, 0, False, None, None
        result_seen = result_error = stopped_seen = inferior_exited = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try: line = self.lines.get(timeout=min(0.2, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                if self.proc.poll() is not None: break
                continue
            if line is None:
                break
            m = re.search(r'thread-group-started,id="[^"]+",pid="(\d+)"', line)
            if m:
                new_pid = int(m.group(1))
                if self.original_inferior_pid is None:
                    self.original_inferior_pid = new_pid
                if self.inferior_pid is not None and new_pid != self.inferior_pid:
                    self.identity_changed = True
                self.inferior_pid = new_pid
            if line.startswith("=breakpoint-created") and 'catch-type="exec"' in line:
                catch = re.search(r'number="(\d+)"', line)
                if catch:
                    self.exec_catchpoint = catch.group(1)
            if line.startswith("*stopped") and (
                    'reason="exec"' in line or
                    (self.exec_catchpoint is not None and
                     'bkptno="%s"' % self.exec_catchpoint in line)):
                self.identity_changed = True
            # GDB may report an exec with the same PID.  A stopped inferior's
            # executable is the identity boundary, regardless of PID reuse.
            if line.startswith("*stopped") and self.inferior_pid:
                exe = "/proc/%d/exe" % self.inferior_pid
                if os.path.exists(exe):
                    try:
                        if sha256_file(exe) != self.binary_digest:
                            self.identity_changed = True
                    except OSError:
                        self.identity_changed = True
            data = (line + "\n").encode()
            size += len(data)
            allowed = min(len(data), max(self.output_cap - kept, 0))
            visible = data[:allowed].decode("utf-8", errors="replace").rstrip("\n")
            kept += allowed
            if allowed < len(data): truncated = True
            if line.startswith(token + "^"):
                result_seen = True
                result_error = line.startswith(token + "^error")
                result = visible[len(token) + 1:] if visible.startswith(token + "^") else ""
                if not stop: break
                if result_error: break
            elif visible:
                output.append(visible)
            if line.startswith("*stopped"):
                stopped_seen = True
                stopped = visible
                inferior_exited = 'reason="exited' in line
                if stop and result_seen: break
        timed_out = not result_seen or (stop and not stopped_seen and not result_error)
        status = "timeout" if timed_out else ("error" if result_error else ("partial" if truncated else "ok"))
        return {"status": status, "mi_result": result, "stop": stopped, "output": output,
                "output_bytes": size, "truncated": truncated, "inferior_exited": inferior_exited}

    def close(self):
        terminate_owned(self.proc)


def _capture(config, history, mi):
    payload = {"schema": "rat.gdb-session-candidate/v1", "kind": "candidate", "direct_evidence": False,
               "session_id": config["session_id"], "run_id": config["run_id"],
               "process_identity": {"gdb_pid": mi.proc.pid, "inferior_pid": mi.original_inferior_pid},
               "binary_digest": config["binary_digest"], "environment_digest": config["environment_digest"],
               "scenario_digest": config["scenario_digest"], "tool_version": VERSION,
               "observations": history}
    validate(payload, "rat.gdb-session-candidate/v1")
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    record = put_bytes(raw, kind="gdb-session-candidate", media_type="application/json",
                       logical_name=config["session_id"] + ".json", root=config["store"],
                       provenance={"run_id": config["run_id"], "session_id": config["session_id"]})
    _, config_path = _paths(config["binary"], config["session_id"])
    ledger = config_path[:-5] + ".result.json"
    tmp = ledger + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump({"session_id": config["session_id"], "run_id": config["run_id"],
                   "candidate_digest": record["digest"], "observations": len(history)}, handle, sort_keys=True)
    os.replace(tmp, ledger)
    return {"digest": record["digest"], "kind": record["kind"], "size": record["size"]}


def _inspect(mi, action, params, timeout=10):
    if action == "break":
        target = params.get("target", "")
        if not (ADDR.fullmatch(target) or SYMBOL.fullmatch(target)):
            raise ValueError("break target must be an address or symbol")
        return mi.command("-break-insert " + ("*" if ADDR.fullmatch(target) else "") + target, timeout=timeout)
    if action == "continue":
        return mi.command("-exec-continue", stop=True, timeout=timeout)
    if action == "registers":
        # Limit MI to the first 34 integer/control slots (AArch64 PC is 32).
        # Requesting every slot includes large vector/FP structures and can
        # swamp both the debugger pipe and the action's output budget.
        result = mi.command("-data-list-register-values x " + " ".join(str(i) for i in range(34)), timeout=timeout)
        result["registers"] = dict(re.findall(r'number="(\d+)",value="(0x[0-9a-fA-F]+)"', result.get("mi_result") or ""))
        if result["status"] == "ok" and not result["registers"]:
            result["status"] = "partial"; result["diagnostic"] = "register values absent or unparsed"
        return result
    if action == "memory":
        target, count = params.get("address", ""), params.get("count")
        if not ADDR.fullmatch(target) or not isinstance(count, int) or not 1 <= count <= 256:
            raise ValueError("memory needs address and count 1..256")
        result = mi.command("-data-read-memory-bytes %s %d" % (target, count), timeout=timeout)
        result["memory_hex"] = re.findall(r'contents="([0-9a-fA-F]+)"', result.get("mi_result") or "")
        if result["status"] == "ok" and not result["memory_hex"]:
            result["status"] = "partial"; result["diagnostic"] = "memory bytes absent or unparsed"
        return result
    if action == "mappings":
        return mi.command('-interpreter-exec console "info proc mappings"', timeout=timeout)
    raise ValueError("unsupported inspect action")


def serve(config_path):
    with open(config_path, encoding="utf-8") as handle: config = json.load(handle)
    run, digest = _manifest(config["binary"])
    expected_sock, expected_config = _paths(config["binary"], config["session_id"])
    if (os.path.realpath(config_path) != os.path.realpath(expected_config)
            or config["socket"] != expected_sock or run["run_id"] != config["run_id"]
            or digest != config["binary_digest"]
            or config["store"] != os.path.join(os.path.dirname(config["binary"]), ".rat")):
        raise ValueError("GDB session configuration does not match active local run")
    sock = config["socket"]
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    mi = None; history = []
    try:
        if os.path.exists(sock): os.unlink(sock)
        listener.bind(sock); os.chmod(sock, 0o600); listener.listen(2)
        mi = MI(config)
        started = time.monotonic(); last = started
        initial = mi.command("-exec-run --start", stop=True, timeout=config["action_timeout"])
        if initial["status"] not in {"ok", "partial"} or not mi.inferior_pid:
            raise RuntimeError("GDB could not start the target: %s %s" %
                               (initial["status"], initial.get("mi_result")))
        catch = mi.command('-interpreter-exec console "catch exec"', timeout=config["action_timeout"])
        if catch["status"] not in {"ok", "partial"} or mi.exec_catchpoint is None:
            raise RuntimeError("GDB could not install exec catchpoint")
        listener.settimeout(0.5)
        while True:
            if time.monotonic() - started >= config["total_timeout"] or time.monotonic() - last >= config["idle_timeout"]:
                break
            if mi.proc.poll() is not None or not mi.inferior_pid:
                break
            ended = False
            while True:
                try: asynchronous = mi.lines.get_nowait()
                except queue.Empty: break
                if asynchronous and ("*stopped" in asynchronous and "reason=\"exited" in asynchronous
                                     or asynchronous.startswith("=thread-group-exited")):
                    ended = True
            if ended:
                break
            try:
                current_run, current_digest = _manifest(config["binary"])
                if current_run["run_id"] != config["run_id"] or current_digest != config["binary_digest"]:
                    break
            except (OSError, ValueError):
                break
            try: connection, _ = listener.accept()
            except socket.timeout: continue
            with connection:
                try:
                    # A client that connects but never sends must not suspend
                    # idle/total expiry or run identity checks indefinitely.
                    deadline = min(started + config["total_timeout"],
                                   last + config["idle_timeout"],
                                   time.monotonic() + config["action_timeout"])
                    data = bytearray()
                    while not data.endswith(b"\n"):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout("request deadline expired")
                        connection.settimeout(remaining)
                        chunk = connection.recv(min(16384 - len(data), 4096))
                        if not chunk or len(data) + len(chunk) >= 16384:
                            raise ValueError("request missing or too large")
                        data.extend(chunk)
                    req = json.loads(data)
                    run, digest = _manifest(config["binary"])
                    if run["run_id"] != config["run_id"] or digest != config["binary_digest"] or req.get("run_id") != config["run_id"]:
                        raise ValueError("session identity mismatch")
                    last = time.monotonic()
                    action = req.get("action")
                    if action == "status":
                        response = {"status": "ok", "session_id": config["session_id"], "run_id": config["run_id"],
                                    "inferior_pid": mi.inferior_pid, "gdb_pid": mi.proc.pid,
                                    "binary_digest": digest, "scenario_digest": config["scenario_digest"]}
                    elif action == "capture":
                        response = {"status": "ok", "artifact": _capture(config, history, mi), "observations": len(history)}
                    elif action == "close":
                        response = {"status": "closed", "session_id": config["session_id"]}
                    else:
                        if len(history) >= MAX_OBSERVATIONS:
                            raise ValueError("session observation limit reached; capture and close")
                        action_remaining = min(started + config["total_timeout"],
                                               last + config["idle_timeout"],
                                               time.monotonic() + config["action_timeout"]) - time.monotonic()
                        if action_remaining <= 0:
                            result = {"status": "timeout", "diagnostic": "session deadline expired"}
                        else:
                            result = _inspect(mi, action, req, timeout=action_remaining)
                        if mi.identity_changed:
                            result["status"] = "partial"
                            result["identity_changed"] = True
                        entry = {"sequence": len(history) + 1, "action": action, "result": result,
                                 "process_identity": {"gdb_pid": mi.proc.pid, "inferior_pid": mi.inferior_pid}}
                        if not mi.identity_changed:
                            history.append(entry)
                        response = {"status": result["status"], "session_id": config["session_id"],
                                    "observation": entry}
                        if mi.identity_changed or result.get("inferior_exited"):
                            if history:
                                response["artifact"] = _capture(config, history, mi)
                            response["session_ended"] = True
                            response["termination"] = "identity-changed" if mi.identity_changed else "inferior-exited"
                    connection.settimeout(max(0.001, min(deadline - time.monotonic(),
                                                         started + config["total_timeout"] - time.monotonic())))
                    connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")
                    if action == "close" or response.get("session_ended") or response["status"] == "timeout": break
                except Exception as exc:
                    try:
                        connection.settimeout(0.1)
                        connection.sendall(json.dumps({"status": "error", "error": str(exc)}).encode() + b"\n")
                    except OSError:
                        pass
    finally:
        if mi and history:
            try: _capture(config, history, mi)
            except (OSError, ValueError): pass
        if mi: mi.close()
        listener.close()
        for path in (sock, config_path):
            try: os.unlink(path)
            except FileNotFoundError: pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) == 2 and argv[0] == "serve":
        serve(argv[1]); return 0
    parser = argparse.ArgumentParser(prog="rat dyn session")
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("start"); p.add_argument("binary"); p.add_argument("--scenario", required=True)
    p.add_argument("--total-timeout", type=int, default=120); p.add_argument("--idle-timeout", type=int, default=30)
    p.add_argument("--action-timeout", type=int, default=10)
    p.add_argument("--output-cap", type=int, default=8192)
    for name in ("status", "break", "continue", "registers", "memory", "mappings", "capture", "close"):
        p = sub.add_parser(name); p.add_argument("binary"); p.add_argument("session_id")
        if name == "break": p.add_argument("target")
        if name == "memory": p.add_argument("address"); p.add_argument("count", type=int)
    args = parser.parse_args(argv)
    try:
        if args.action == "start":
            result = start(args.binary, args.scenario, total_timeout=args.total_timeout,
                           idle_timeout=args.idle_timeout, action_timeout=args.action_timeout,
                           output_cap=args.output_cap)
        else:
            params = {key: getattr(args, key) for key in ("target", "address", "count") if hasattr(args, key)}
            result = request(args.binary, args.session_id, args.action, **params)
    except ConnectionLostError as exc:
        result = {"status": "connection_lost", "error": str(exc)}
    except (ValueError, OSError, RuntimeError) as exc:
        result = {"status": "error", "error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"ok", "partial", "closed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
