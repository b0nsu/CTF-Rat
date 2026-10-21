"""Materialize pinned benchmark binaries without committing third-party artifacts.

The canonical benchmark metadata remains ``bench/suite.json``.  Entries may
optionally carry a ``fetch`` object that identifies an explicitly
redistributable binary plus a content-addressed Git blob SHA-1.  This module is
an explicit preflight step: ratbench itself does not perform network access
inside a measured run.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import socket
import stat
import tempfile
import threading
import time
import urllib.request

from ratlib.bench_suite import SuiteValidationError, load_suite, project_suite


class ArtifactMaterializationError(RuntimeError):
    pass


# Pinned CTF binaries are small; cap the download well below anything that could
# exhaust memory.  The pin (git_blob_sha1) is verified afterwards, but we must not
# read an unbounded body into RAM before we can reject it (R2-5).
_MAX_ARTIFACT_BYTES = 64 << 20  # 64 MiB


def _read_capped(response, cap, deadline=None):
    """Stream the body up to ``cap`` bytes; fail closed if the source exceeds it.

    ``deadline`` (a ``time.monotonic`` value) bounds the TOTAL wall-clock of the
    download. The socket ``timeout`` passed to ``urlopen`` only bounds a single
    stalled read, so a source that keeps dripping just under that timeout could
    otherwise extend the download indefinitely while never tripping the byte cap.
    ``read1`` returns available bytes without waiting for a full 64 KiB buffer.
    A timer also shuts down the HTTP socket at the deadline, including while
    parsing chunk framing inside a blocking read.
    """
    chunks = []
    total = 0
    raw = getattr(getattr(response, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None)
    if deadline is not None and isinstance(response, http.client.HTTPResponse) and sock is None:
        raise ArtifactMaterializationError(
            "artifact download cannot enforce total time budget on this HTTP transport")
    expired = threading.Event()
    timer = None
    if deadline is not None and sock is not None:
        def interrupt_read():
            expired.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(max(0, deadline - time.monotonic()), interrupt_read)
        timer.daemon = True
        timer.start()
    read = getattr(response, "read1", response.read)
    try:
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise ArtifactMaterializationError(
                    "artifact download exceeded total time budget")
            try:
                chunk = read(65536)
            except Exception as exc:
                if expired.is_set() or (deadline is not None and time.monotonic() >= deadline):
                    raise ArtifactMaterializationError(
                        "artifact download exceeded total time budget") from exc
                raise
            if expired.is_set() or (deadline is not None and time.monotonic() >= deadline):
                raise ArtifactMaterializationError(
                    "artifact download exceeded total time budget")
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ArtifactMaterializationError(
                    "artifact exceeds %d-byte download cap" % cap)
            chunks.append(chunk)
    finally:
        if timer is not None:
            timer.cancel()
    return b"".join(chunks)


def git_blob_sha1(data):
    """Return the Git object id for one blob payload."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("blob payload must be bytes")
    payload = bytes(data)
    header = ("blob %d\0" % len(payload)).encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def _contains(parent, child):
    """True if ``child`` is ``parent`` or lives under it (both already real paths)."""
    try:
        return os.path.commonpath((parent, child)) == parent
    except ValueError:  # different drives / mixed abs-rel
        return False


def _target_path(root, entry):
    store_root = os.path.realpath(root)
    base = os.path.realpath(os.path.join(store_root, entry["dir"]))
    # The fixture directory itself must stay within the store root: a symlinked
    # ``dir`` would otherwise let the target escape even though ``target`` resolves
    # under its own (escaped) base.
    if not _contains(store_root, base):
        raise ArtifactMaterializationError(
            "fixture dir escapes store root: %s" % entry.get("dir"))
    binary = entry.get("binary")
    if not binary:
        raise ArtifactMaterializationError("%s has no binary target" % entry["id"])
    target = os.path.realpath(os.path.join(base, binary))
    if not _contains(base, target) or not _contains(store_root, target):
        raise ArtifactMaterializationError("binary target escapes fixture root: %s" % binary)
    return target


def _verify_payload(entry, payload):
    fetch = entry.get("fetch") or {}
    expected = fetch.get("git_blob_sha1")
    if not expected:
        raise ArtifactMaterializationError("%s has no pinned git_blob_sha1" % entry["id"])
    actual = git_blob_sha1(payload)
    if actual.lower() != expected.lower():
        raise ArtifactMaterializationError(
            "%s artifact digest mismatch: expected %s, got %s" %
            (entry["id"], expected, actual)
        )


def _mark_executable(path):
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def materialize_entry(entry, *, root, opener=None, timeout=60, total_timeout=None):
    """Fetch one pinned binary, or validate an already-materialized copy.

    Returns ``"present"`` when an existing file already matches the pin and
    ``"downloaded"`` when a new file is installed.  A mismatched existing file
    fails closed rather than being silently replaced.

    ``timeout`` bounds a single socket operation; ``total_timeout`` bounds the
    whole download's wall-clock (default ``max(timeout * 10, 600)`` seconds) so a
    slow-drip source cannot extend the fetch indefinitely.
    """
    fetch = entry.get("fetch")
    if not isinstance(fetch, dict):
        raise ArtifactMaterializationError("%s has no fetch metadata" % entry["id"])
    target = _target_path(root, entry)

    if os.path.isfile(target):
        # Apply the same byte cap to an already-materialized file: an unexpectedly
        # large pre-existing target must be rejected before its digest check, not
        # read whole into memory (R2-5; parity with the download path).
        size = os.path.getsize(target)
        if size > _MAX_ARTIFACT_BYTES:
            raise ArtifactMaterializationError(
                "%s existing artifact exceeds %d-byte cap (%d)"
                % (entry["id"], _MAX_ARTIFACT_BYTES, size))
        with open(target, "rb") as fh:
            payload = fh.read()
        _verify_payload(entry, payload)
        _mark_executable(target)
        return "present"

    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(
        fetch["url"],
        headers={"User-Agent": "CTF-Rat-ratbench/1"},
    )
    if total_timeout is None:
        total_timeout = max(timeout * 10, 600)
    deadline = time.monotonic() + total_timeout
    try:
        response = opener(request, timeout=min(timeout, total_timeout))
        with response:
            payload = _read_capped(response, _MAX_ARTIFACT_BYTES, deadline=deadline)
    except ArtifactMaterializationError:
        raise
    except Exception as exc:
        raise ArtifactMaterializationError(
            "%s artifact download failed: %s" % (entry["id"], exc)
        ) from exc

    _verify_payload(entry, payload)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ratbench-fetch-", dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        _mark_executable(target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return "downloaded"


def _select_entries(suite, *, corpus=None, entry_id=None):
    projected = project_suite(suite, corpus=corpus) if corpus else suite
    entries = list(projected["entries"])
    if entry_id:
        entries = [entry for entry in entries if entry["id"] == entry_id]
        if not entries:
            raise ArtifactMaterializationError("no entry %s" % entry_id)
    fetchable = [entry for entry in entries if entry.get("fetch")]
    if not fetchable:
        scope = entry_id or corpus or "selected suite"
        raise ArtifactMaterializationError("no fetchable artifacts for %s" % scope)
    return fetchable


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python3 -m ratlib.bench_artifacts",
        description="materialize pinned real benchmark artifacts before ratbench eval",
    )
    parser.add_argument("suite", help="benchmark suite JSON path")
    parser.add_argument("--corpus", choices=("synthetic", "integration", "real", "private"))
    parser.add_argument("--id", dest="entry_id", help="materialize one benchmark id")
    parser.add_argument("--root", help="CTF-Rat root (defaults to parent of suite directory)")
    args = parser.parse_args(argv)

    suite_path = os.path.abspath(args.suite)
    root = os.path.abspath(args.root or os.path.join(os.path.dirname(suite_path), ".."))
    try:
        suite = load_suite(suite_path)
        entries = _select_entries(suite, corpus=args.corpus, entry_id=args.entry_id)
        for entry in entries:
            status = materialize_entry(entry, root=root)
            rel = os.path.relpath(_target_path(root, entry), root)
            print("[%s] %s -> %s" % (status, entry["id"], rel))
    except (SuiteValidationError, ArtifactMaterializationError) as exc:
        print("[bench-artifacts:err] %s" % exc, file=__import__("sys").stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
