"""Bounded local solver process control for CTF-Rat Desktop.

The desktop daemon never accepts arbitrary argv from HTTP clients. A solver
command is configured once when ratd starts; the UI may only start/stop that
preconfigured command and exchange PTY input with it.
"""
from __future__ import annotations
import json, os, pty, signal, subprocess, threading, time, uuid
from datetime import datetime, timezone
from typing import Any

SESSION_SCHEMA = "rat.desktop.session/v1"
LOG_SCHEMA = "rat.desktop.terminal/v1"
MAX_LOG_READ = 256 * 1024
MAX_INPUT = 4096


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: str, doc: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as out:
        json.dump(doc, out, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)


class SessionManager:
    def __init__(self, challenge_root: str, solver_argv: list[str] | None):
        self.root = os.path.abspath(challenge_root)
        self.solver_argv = list(solver_argv or [])
        self.base = os.path.join(self.root, ".rat", "desktop")
        self.meta_path = os.path.join(self.base, "session.json")
        self.log_path = os.path.join(self.base, "terminal.log")
        self._lock = threading.RLock()
        self._proc: subprocess.Popen[bytes] | None = None
        self._master_fd: int | None = None
        self._reader: threading.Thread | None = None
        self._started_at: float | None = None
        self._session_id: str | None = None
        self._exit_code: int | None = None
        self._stopped_at: str | None = None
        # Terminal cursors are opaque and monotonically increase across solver
        # and ratd restarts. Persist the base inside the existing session
        # metadata rather than creating a second state/cache subsystem.
        previous_meta = self._read_meta()
        previous_base = previous_meta.get("_log_cursor_base", 0)
        self._log_base = previous_base if isinstance(previous_base, int) and previous_base >= 0 else 0

    def _running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _status_doc(self) -> dict[str, Any]:
        running = self._running()
        pid = self._proc.pid if self._proc is not None and running else None
        elapsed = time.monotonic() - self._started_at if running and self._started_at is not None else None
        return {
            "schema": SESSION_SCHEMA,
            "configured": bool(self.solver_argv),
            "session_id": self._session_id,
            "status": "running" if running else ("finished" if self._session_id else "idle"),
            "pid": pid,
            "argv": self.solver_argv,
            "started_at": None if self._started_at is None else self._read_meta().get("started_at"),
            "stopped_at": self._stopped_at,
            "exit_code": None if running else self._exit_code,
            "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
            "log_size": os.path.getsize(self.log_path) if os.path.exists(self.log_path) else 0,
        }

    def _read_meta(self) -> dict[str, Any]:
        try:
            with open(self.meta_path, encoding="utf-8") as source:
                doc = json.load(source)
            return doc if isinstance(doc, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_meta(self, doc: dict[str, Any]) -> None:
        _atomic_json(self.meta_path, {**doc, "_log_cursor_base": self._log_base})

    def _finished_reader(self) -> threading.Thread | None:
        with self._lock:
            if self._running():
                return None
            reader = self._reader
            if reader is None or reader is threading.current_thread() or not reader.is_alive():
                return None
            return reader

    def _join_finished_reader(self, timeout: float = 0.5, *, required: bool = False) -> bool:
        """Drain a completed process' PTY without holding the manager lock."""
        reader = self._finished_reader()
        if reader is None:
            return True
        reader.join(timeout=timeout)
        if reader.is_alive() and required:
            raise ValueError("previous solver session is still cleaning up")
        return not reader.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            finished = self._proc is not None and self._proc.poll() is not None
            if finished and self._exit_code is None:
                self._exit_code = self._proc.returncode
                self._stopped_at = _now()
                self._write_meta(self._status_doc())
        if finished:
            self._join_finished_reader(timeout=0.5)
        with self._lock:
            return self._status_doc()

    def start(self) -> dict[str, Any]:
        if not self.solver_argv:
            raise ValueError("ratd was started without --solver-command")
        with self._lock:
            if self._running():
                raise ValueError("solver session is already running")
        # Reader finalization takes the manager lock, so joining it while
        # holding that lock can deadlock. Drain it first, then re-check state.
        self._join_finished_reader(timeout=0.5, required=True)
        with self._lock:
            if self._running():
                raise ValueError("solver session is already running")
            os.makedirs(self.base, mode=0o700, exist_ok=True)
            try:
                previous_log_size = os.path.getsize(self.log_path)
            except OSError:
                previous_log_size = 0
            # Advance by one separator as well as the previous byte length so
            # every cursor from an older session is strictly below this base.
            self._log_base += previous_log_size + 1
            open(self.log_path, "wb").close()
            master_fd, slave_fd = pty.openpty()
            env = dict(os.environ)
            env["CTF_RAT_DESKTOP"] = "1"
            try:
                proc = subprocess.Popen(
                    self.solver_argv,
                    cwd=self.root,
                    env=env,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    start_new_session=True,
                    close_fds=True,
                )
            finally:
                os.close(slave_fd)
            self._proc = proc
            self._master_fd = master_fd
            self._started_at = time.monotonic()
            self._session_id = "desktop_" + uuid.uuid4().hex
            self._exit_code = None
            self._stopped_at = None
            started_at = _now()
            self._write_meta({**self._status_doc(), "started_at": started_at})
            session_id = self._session_id
            self._reader = threading.Thread(target=self._pump, args=(proc, master_fd, session_id), name="ratd-pty", daemon=True)
            self._reader.start()
            return self._status_doc()

    def _pump(self, proc: subprocess.Popen[bytes], fd: int, session_id: str) -> None:
        try:
            with open(self.log_path, "ab", buffering=0) as log:
                while True:
                    try:
                        chunk = os.read(fd, 8192)
                    except OSError:
                        break
                    if not chunk:
                        break
                    log.write(chunk)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            exit_code = proc.wait()
            with self._lock:
                if self._proc is proc and self._session_id == session_id:
                    self._exit_code = exit_code
                    self._stopped_at = _now()
                    if self._master_fd == fd:
                        self._master_fd = None
                    self._write_meta(self._status_doc())

    def stop(self, grace_seconds: float = 2.0) -> dict[str, Any]:
        with self._lock:
            proc = self._proc if self._running() else None
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        if proc is None:
            return self.status()
        try:
            proc.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=1.0)
        with self._lock:
            self._exit_code = proc.returncode
            self._stopped_at = _now()
            self._write_meta(self._status_doc())
        return self.status()

    def write(self, data: str) -> dict[str, Any]:
        raw = data.encode("utf-8")
        if not raw or len(raw) > MAX_INPUT:
            raise ValueError("terminal input must be between 1 and 4096 UTF-8 bytes")
        with self._lock:
            if not self._running() or self._master_fd is None:
                raise ValueError("solver session is not running")
            os.write(self._master_fd, raw)
            return {"schema": "rat.desktop.input/v1", "accepted_bytes": len(raw)}

    def log_delta(self, after: int = 0, limit: int = 65536) -> dict[str, Any]:
        if after < 0:
            raise ValueError("after must be non-negative")
        if limit < 1 or limit > MAX_LOG_READ:
            raise ValueError("limit must be between 1 and %d" % MAX_LOG_READ)
        # Keep session restart/truncate atomic with respect to cursor mapping.
        # The PTY writer does not require this lock; bytes appended after the
        # size snapshot are naturally collected by the next poll.
        with self._lock:
            base = self._log_base
            try:
                size = os.path.getsize(self.log_path)
            except OSError:
                size = 0
            offset = 0 if after < base else after - base
            if offset > size:
                offset = size
            data = b""
            if size:
                with open(self.log_path, "rb") as source:
                    source.seek(offset)
                    data = source.read(limit)
            end_offset = offset + len(data)
            start_cursor = base + offset
            end_cursor = base + end_offset
            return {
                "schema": LOG_SCHEMA,
                "after": start_cursor,
                "cursor": end_cursor,
                "has_more": end_offset < size,
                "text": data.decode("utf-8", "replace"),
            }
