#!/usr/bin/env python3
"""Measure one local analysis command with a bounded wall-clock budget.

Example:
    python3 bench/profile_large_binary.py --binary /usr/bin/git \
        --cache cold --timeout 120 -- .venv-angr/bin/python bin/revq \
        '{binary}' --funcs --allow-large

The caller prepares a cold or warm cache; this script records the declared
cache condition but does not remove cache files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time


def _version(command: list[str]) -> str | None:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=5)
        lines = (proc.stdout + proc.stderr).strip().splitlines()
        return lines[0][:240] if proc.returncode == 0 and lines else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def environment() -> dict:
    """Record versions and host capacity without reading private env values."""
    repo = Path(__file__).resolve().parents[1]
    angr_python = repo / ".venv-angr" / "bin" / "python"
    versions = {"java": _version(["java", "-version"]), "ghidra": None,
                "angr": None}
    try:
        ghidra_home = subprocess.run([sys.executable, str(repo / "bin" / "ratlib" / "ghidra.py"),
                                      "--cache-home"], capture_output=True, text=True,
                                     timeout=5).stdout.strip()
        props = Path(ghidra_home) / "Ghidra" / "application.properties"
        if props.is_file():
            versions["ghidra"] = next((line.split("=", 1)[1].strip() for line in props.read_text().splitlines()
                                       if line.startswith("application.version=")), None)
    except (OSError, subprocess.TimeoutExpired):
        pass
    if angr_python.is_file():
        versions["angr"] = _version([str(angr_python), "-c", "import angr;print(angr.__version__)"])
    ram_kib = None
    try:
        ram_kib = next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                       if line.startswith("MemTotal:"))
    except (OSError, StopIteration, ValueError):
        pass
    return {"platform": platform.platform(), "python": sys.version.split()[0],
            "cpu_count": os.cpu_count(), "ram_total_kib": ram_kib,
            "versions": versions}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def _stream_digest(stream) -> tuple[int, str]:
    stream.seek(0)
    size = 0
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        h.update(block)
    return size, "sha256:" + h.hexdigest()


def _process_tree(root_pid: int) -> dict[int, tuple[int, int]]:
    """Return pid -> (ppid, RSS KiB), including descendants in new sessions."""
    proc = Path("/proc")
    if not proc.is_dir():
        return {}
    rows = {}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat.rsplit(")", 1)[1].split()
            parent = int(fields[1])  # ppid is field 4, after pid and comm
            rss = 0
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                    break
            rows[int(entry.name)] = (parent, rss)
        except (OSError, ValueError, IndexError):
            continue
    if root_pid not in rows:
        return {}
    descendants = {root_pid}
    while True:
        added = {pid for pid, (parent, _rss) in rows.items() if parent in descendants}
        if added <= descendants:
            break
        descendants |= added
    return {pid: rows[pid] for pid in descendants}


def process_tree_rss(root_pid: int) -> int | None:
    """Return RSS of a process and descendants, including new sessions."""
    rows = _process_tree(root_pid)
    return sum(rss for _parent, rss in rows.values()) if rows else None


def _stop_tree(root_pid: int, sig: int) -> None:
    """Stop nested workers before their parent, so they cannot be orphaned."""
    rows = _process_tree(root_pid)
    for pid in sorted(rows, reverse=True):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
    try:
        os.killpg(root_pid, sig)
    except ProcessLookupError:
        pass


def run(binary: Path, command: list[str], timeout: float, cache: str,
        tool_version: str | None) -> dict:
    command = [arg.replace("{binary}", str(binary)) for arg in command]
    host_environment = environment()
    started = time.time()
    started_mono = time.monotonic()
    peak_kib = 0
    timed_out = False
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        try:
            while process.poll() is None:
                rss = process_tree_rss(process.pid)
                if rss is not None:
                    peak_kib = max(peak_kib, rss)
                if time.monotonic() - started_mono >= timeout:
                    timed_out = True
                    _stop_tree(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        _stop_tree(process.pid, signal.SIGKILL)
                        process.wait()
                    break
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                _stop_tree(process.pid, signal.SIGKILL)
                process.wait()
        stdout_size, stdout_hash = _stream_digest(stdout)
        stderr_size, stderr_hash = _stream_digest(stderr)
        stderr.seek(max(0, stderr_size - 2048))
        stderr_tail = stderr.read(2048).decode("utf-8", "replace")
    wall_seconds = round(time.monotonic() - started_mono, 3)
    return {
        "schema": "rat.large-binary-profile/v1",
        "input": {"path": str(binary), "sha256": digest(binary),
                  "size_bytes": binary.stat().st_size},
        "command": command,
        "tool_version": tool_version,
        "cache_condition": cache,
        "environment": host_environment,
        "started_at_epoch": started,
        "wall_seconds": wall_seconds,
        "timeout_seconds": timeout,
        "timed_out": timed_out,
        "exit_code": process.returncode,
        "sampled_peak_process_tree_rss_kib": peak_kib or None,
        "sampling_interval_seconds": 0.05,
        "stdout": {"bytes": stdout_size, "sha256": stdout_hash},
        "stderr": {"bytes": stderr_size, "sha256": stderr_hash,
                   "tail": stderr_tail},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cache", choices=("cold", "warm", "unknown"), required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--tool-version", help="version of the tool in the measured command")
    parser.add_argument("--output", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.binary.is_file() or args.timeout <= 0:
        parser.error("--binary must be a file and --timeout must be positive")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("provide a command after --; use {binary} for the input path")
    result = run(args.binary.resolve(), command, args.timeout, args.cache,
                 args.tool_version)
    payload = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(payload)
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
