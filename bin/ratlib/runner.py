"""Bounded subprocess runner used by new ctf-rat tools."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

EXIT_OK, EXIT_USAGE, EXIT_DEPENDENCY, EXIT_INPUT, EXIT_POLICY = 0, 2, 3, 4, 5
EXIT_INTERNAL, EXIT_TIMEOUT, EXIT_CANCELLED = 70, 124, 130


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 60
    address_space_bytes: int = 2 * 1024 * 1024 * 1024
    file_size_bytes: int = 512 * 1024 * 1024
    open_files: int = 256
    processes: int = 64
    core_bytes: int = 0


@dataclass
class CapturedStream:
    preview: bytes
    total_bytes: int
    truncated: bool
    spool_path: Optional[str]


@dataclass
class RunResult:
    argv: list[str]
    returncode: int
    exit_code: int
    timed_out: bool
    cancelled: bool
    duration_ms: int
    stdout: CapturedStream
    stderr: CapturedStream
    network_policy: str
    signal: Optional[int]
    resource_limited: bool
    tool_version: Optional[str]


class RunnerPolicyError(RuntimeError):
    pass


class _Capture:
    def __init__(self, preview_bytes: int, max_bytes: int, spool_dir: Optional[str], label: str,
                 spool_threshold_bytes: int):
        self.preview_bytes, self.max_bytes = preview_bytes, max_bytes
        self.preview, self.total, self.truncated = bytearray(), 0, False
        self._file, self.path = None, None
        self._spool_dir, self._label, self._spool_threshold = spool_dir, label, spool_threshold_bytes
        self._pending = bytearray() if spool_dir else None

    def add(self, data: bytes) -> None:
        before = self.total
        self.total += len(data)
        if len(self.preview) < self.preview_bytes:
            self.preview.extend(data[: self.preview_bytes - len(self.preview)])
        allowed = max(self.max_bytes - before, 0)
        if len(data) > allowed:
            self.truncated = True
        kept = data[:allowed]
        if self._pending is not None and self._file is None:
            self._pending.extend(kept)
            if before + len(kept) > self._spool_threshold:
                os.makedirs(self._spool_dir, mode=0o700, exist_ok=True)
                fd, self.path = tempfile.mkstemp(prefix="rat-%s-" % self._label, dir=self._spool_dir)
                self._file = os.fdopen(fd, "wb")
                self._file.write(self._pending); self._pending = None
        elif self._file and kept:
            self._file.write(kept)

    def close(self) -> CapturedStream:
        if self._file:
            self._file.flush(); os.fsync(self._file.fileno()); self._file.close()
        return CapturedStream(bytes(self.preview), self.total, self.truncated, self.path)


def _user_process_count() -> int:
    """Count current UID tasks; Linux RLIMIT_NPROC accounts for threads too."""
    if not os.path.isdir("/proc") or not hasattr(os, "getuid"):
        return 0
    uid, count = os.getuid(), 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            proc = os.path.join("/proc", entry)
            if os.stat(proc).st_uid == uid:
                try:
                    count += len(os.listdir(os.path.join(proc, "task")))
                except OSError:
                    count += 1
        except OSError:
            pass
    return count


def _limit_preexec(limits: ResourceLimits, existing_processes: int):
    def apply_limits():
        import resource
        _, inherited_cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
        cpu_hard = limits.cpu_seconds + 1
        if inherited_cpu_hard != resource.RLIM_INFINITY:
            cpu_hard = min(cpu_hard, inherited_cpu_hard)
        cpu_soft = min(limits.cpu_seconds, cpu_hard)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
        # macOS neither enforces RLIMIT_AS nor accepts setting it when the inherited
        # soft limit is RLIM_INFINITY (setrlimit raises "current limit exceeds
        # maximum limit"), which would kill every spawn from preexec_fn. Skip it
        # there; the CPU/time limits still bound the child.
        if sys.platform != "darwin":
            resource.setrlimit(resource.RLIMIT_AS, (limits.address_space_bytes, limits.address_space_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.file_size_bytes, limits.file_size_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
        # RLIMIT_NPROC is per real UID, not per child. Preserve room for the
        # user's existing processes and cap this invocation's additional tree.
        # macOS has no /proc to count existing processes from, so the ceiling
        # would be computed as just `limits.processes` — a per-UID cap far below
        # the user's real process count that makes every fork fail with
        # EAGAIN/BlockingIOError. Skip NPROC there (CPU/time limits still bound).
        if sys.platform != "darwin":
            _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
            wanted = existing_processes + limits.processes
            ceiling = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
            resource.setrlimit(resource.RLIMIT_NPROC, (ceiling, hard))
        resource.setrlimit(resource.RLIMIT_CORE, (limits.core_bytes, limits.core_bytes))
    return apply_limits


def _reader(pipe, capture: _Capture) -> None:
    try:
        while data := pipe.read(64 * 1024):
            capture.add(data)
    finally:
        pipe.close()


def _writer(pipe, data: bytes) -> None:
    try:
        pipe.write(data)
        pipe.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        pipe.close()


def _terminate_group(proc: subprocess.Popen, grace_seconds: float) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _minimal_environment() -> dict[str, str]:
    allow = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "TMPDIR"}
    return {key: value for key, value in os.environ.items() if key in allow}


def _guard_target(target: Sequence[str], ctf_home: Optional[str]) -> None:
    if not target:
        raise RunnerPolicyError("ctfguard-target requires a target tuple")
    root = ctf_home or os.environ.get("CTF_HOME") or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    guard = os.path.join(root, "bin", "ctfguard")
    if not os.path.isfile(guard):
        raise RunnerPolicyError("ctfguard is unavailable for target preflight")
    checked = subprocess.run([guard, "check-target", *target], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             text=True, timeout=5, env=_minimal_environment() | {"CTF_HOME": root})
    if checked.returncode != 0:
        raise RunnerPolicyError("ctfguard target preflight rejected: %s" % checked.stderr.strip())


def run(argv: Sequence[str], *, cwd: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
        timeout_seconds: float = 60.0, grace_seconds: float = 1.0,
        limits: ResourceLimits = ResourceLimits(), preview_bytes: int = 8 * 1024 * 1024,
        max_output_bytes: int = 64 * 1024 * 1024, spool_dir: Optional[str] = None,
        spool_threshold_bytes: int = 8 * 1024 * 1024,
        network: str = "inherit", guard_target: Sequence[str] = (), ctf_home: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        tool_version: Optional[str] = None,
        input_bytes: Optional[bytes] = None) -> RunResult:
    """Run argv-only child in a new process group with bounded resources.

    This helper has no OS network sandbox. ``network='none'`` therefore fails
    closed rather than making a false isolation promise.
    """
    if not argv or not all(isinstance(arg, str) and arg for arg in argv):
        raise ValueError("argv must be a non-empty sequence of non-empty strings")
    if input_bytes is not None and not isinstance(input_bytes, bytes):
        raise ValueError("input_bytes must be bytes or None")
    if timeout_seconds <= 0 or grace_seconds < 0 or max_output_bytes <= 0:
        raise ValueError("invalid runner timeout/output limits")
    if network == "none":
        raise RunnerPolicyError("network=none requested but no network namespace sandbox is available")
    if network not in ("inherit", "ctfguard-target"):
        raise RunnerPolicyError("network policy cannot be enforced by this runner: %s" % network)
    if network == "ctfguard-target":
        _guard_target(guard_target, ctf_home)
    out = _Capture(preview_bytes, max_output_bytes, spool_dir, "stdout", spool_threshold_bytes)
    err = _Capture(preview_bytes, max_output_bytes, spool_dir, "stderr", spool_threshold_bytes)
    started = time.monotonic()
    child_env = _minimal_environment()
    if env is not None:
        child_env.update(env)
    existing_processes = _user_process_count()
    try:
        proc = subprocess.Popen(list(argv), cwd=cwd, env=child_env,
                                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, start_new_session=True,
                                preexec_fn=_limit_preexec(limits, existing_processes) if os.name == "posix" else None)
    except FileNotFoundError:
        elapsed = int((time.monotonic() - started) * 1000)
        return RunResult(list(argv), EXIT_DEPENDENCY, EXIT_DEPENDENCY, False, False, elapsed,
                         out.close(), err.close(), network, None, False, tool_version)
    assert proc.stdout is not None and proc.stderr is not None
    readers = [threading.Thread(target=_reader, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=_reader, args=(proc.stderr, err), daemon=True)]
    for thread in readers: thread.start()
    writer = None
    if input_bytes is not None:
        assert proc.stdin is not None
        writer = threading.Thread(target=_writer, args=(proc.stdin, input_bytes), daemon=True)
        writer.start()
    timed_out, cancelled = False, False
    deadline = started + timeout_seconds
    try:
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                _terminate_group(proc, grace_seconds)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_group(proc, grace_seconds)
                break
            time.sleep(0.02)
        proc.wait()
    finally:
        if writer is not None:
            writer.join(timeout=5)
        for thread in readers: thread.join(timeout=5)
    elapsed = int((time.monotonic() - started) * 1000)
    returncode = proc.returncode if proc.returncode is not None else EXIT_INTERNAL
    termination_signal = abs(returncode) if returncode < 0 else None
    resource_limited = termination_signal == getattr(signal, "SIGXCPU", 24)
    if timed_out:
        exit_code = EXIT_TIMEOUT
    elif cancelled:
        exit_code = EXIT_CANCELLED
    elif resource_limited:
        exit_code = EXIT_TIMEOUT
    elif returncode < 0:
        exit_code = 128 + abs(returncode)
    else:
        exit_code = returncode
    return RunResult(list(argv), returncode, exit_code, timed_out, cancelled,
                     elapsed, out.close(), err.close(), network, termination_signal,
                     resource_limited, tool_version)
