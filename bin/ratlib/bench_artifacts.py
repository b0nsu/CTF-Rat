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
import os
import stat
import tempfile
import urllib.request

from ratlib.bench_suite import SuiteValidationError, load_suite, project_suite


class ArtifactMaterializationError(RuntimeError):
    pass


def git_blob_sha1(data):
    """Return the Git object id for one blob payload."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("blob payload must be bytes")
    payload = bytes(data)
    header = ("blob %d\0" % len(payload)).encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def _target_path(root, entry):
    base = os.path.realpath(os.path.join(root, entry["dir"]))
    binary = entry.get("binary")
    if not binary:
        raise ArtifactMaterializationError("%s has no binary target" % entry["id"])
    target = os.path.realpath(os.path.join(base, binary))
    if os.path.commonpath((base, target)) != base:
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


def materialize_entry(entry, *, root, opener=None, timeout=60):
    """Fetch one pinned binary, or validate an already-materialized copy.

    Returns ``"present"`` when an existing file already matches the pin and
    ``"downloaded"`` when a new file is installed.  A mismatched existing file
    fails closed rather than being silently replaced.
    """
    fetch = entry.get("fetch")
    if not isinstance(fetch, dict):
        raise ArtifactMaterializationError("%s has no fetch metadata" % entry["id"])
    target = _target_path(root, entry)

    if os.path.isfile(target):
        with open(target, "rb") as fh:
            payload = fh.read()
        _verify_payload(entry, payload)
        return "present"

    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(
        fetch["url"],
        headers={"User-Agent": "CTF-Rat-ratbench/1"},
    )
    try:
        response = opener(request, timeout=timeout)
        with response:
            payload = response.read()
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
        mode = os.stat(target).st_mode
        os.chmod(target, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
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
