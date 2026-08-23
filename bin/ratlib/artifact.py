"""Immutable local SHA-256 object store used by challenge directories."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone

VERIFY_CHUNK = 1024 * 1024


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _root(path: str | None = None) -> str:
    return os.path.abspath(path or os.path.join(os.getcwd(), ".rat"))


def _paths(root: str, digest: str):
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("invalid digest")
    h = digest[7:]
    return (
        os.path.join(root, "objects", "sha256", h[:2], h[2:]),
        os.path.join(root, "metadata", "sha256", h[:2], h[2:] + ".json"),
    )


def _checked_prefix(digest: str, *, root: str, max_bytes: int = 0) -> tuple[bytes, int]:
    """Verify one immutable object while retaining only a bounded prefix."""
    if not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    obj, _ = _paths(root, digest)
    hasher = hashlib.sha256()
    prefix = bytearray()
    total = 0
    with open(obj, "rb") as source:
        while True:
            chunk = source.read(VERIFY_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
            if len(prefix) < max_bytes:
                prefix.extend(chunk[: max_bytes - len(prefix)])
    if "sha256:" + hasher.hexdigest() != digest:
        raise RuntimeError("artifact corruption")
    return bytes(prefix), total


def _metadata_record(digest: str, *, root: str) -> dict:
    _, path = _paths(root, digest)
    with open(path, encoding="utf-8") as source:
        record = json.load(source)
    if record.get("schema") != "rat.artifact/v1" or record.get("digest") != digest:
        raise RuntimeError("artifact metadata corruption")
    return record


def put_bytes(
    data: bytes,
    *,
    kind: str,
    media_type: str,
    logical_name: str,
    root: str | None = None,
    provenance: dict | None = None,
) -> dict:
    root = _root(root)
    digest = digest_bytes(data)
    obj, meta = _paths(root, digest)
    os.makedirs(os.path.dirname(obj), mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(meta), mode=0o700, exist_ok=True)
    if os.path.exists(obj):
        _, existing_size = _checked_prefix(digest, root=root)
        if existing_size != len(data):
            raise RuntimeError("digest collision/corrupt existing object")
    else:
        fd, tmp = tempfile.mkstemp(prefix=".object-", dir=os.path.dirname(obj))
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            hasher = hashlib.sha256()
            with open(tmp, "rb") as check:
                while True:
                    chunk = check.read(VERIFY_CHUNK)
                    if not chunk:
                        break
                    hasher.update(chunk)
            if "sha256:" + hasher.hexdigest() != digest:
                raise RuntimeError("write digest mismatch")
            try:
                os.link(tmp, obj)
            except FileExistsError:
                pass
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
    record = {
        "schema": "rat.artifact/v1",
        "digest": digest,
        "size": len(data),
        "kind": kind,
        "media_type": media_type,
        "logical_name": logical_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance": provenance or {},
    }
    if not os.path.exists(meta):
        fd, tmp = tempfile.mkstemp(prefix=".metadata-", dir=os.path.dirname(meta))
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        try:
            os.link(tmp, meta)
        except FileExistsError:
            pass
        finally:
            os.unlink(tmp)
    return record


def put_file(path: str, **kw):
    with open(path, "rb") as source:
        return put_bytes(
            source.read(),
            logical_name=kw.pop("logical_name", os.path.basename(path)),
            **kw,
        )


def get(digest: str, *, root: str | None = None) -> bytes:
    """Return the complete verified object bytes (legacy/full-read contract)."""
    checked_root = _root(root)
    obj, _ = _paths(checked_root, digest)
    with open(obj, "rb") as source:
        data = source.read()
    if digest_bytes(data) != digest:
        raise RuntimeError("artifact corruption")
    return data


def metadata(digest: str, *, root: str | None = None) -> dict:
    """Return immutable metadata after streaming content verification."""
    checked_root = _root(root)
    _, total = _checked_prefix(digest, root=checked_root)
    record = _metadata_record(digest, root=checked_root)
    if record.get("size") != total:
        raise RuntimeError("artifact metadata corruption")
    return record


def preview(digest: str, *, max_bytes: int, root: str | None = None) -> tuple[dict, bytes, int]:
    """Return metadata plus a verified bounded object prefix in one hash pass."""
    checked_root = _root(root)
    prefix, total = _checked_prefix(digest, root=checked_root, max_bytes=max_bytes)
    record = _metadata_record(digest, root=checked_root)
    if record.get("size") != total:
        raise RuntimeError("artifact metadata corruption")
    return record, prefix, total


def verify(digest: str | None = None, *, root: str | None = None) -> list[str]:
    root = _root(root)
    failures = []
    if digest:
        candidates = [digest]
    else:
        base = os.path.join(root, "objects", "sha256")
        candidates = []
        if os.path.isdir(base):
            candidates = [
                "sha256:" + a + b
                for a in os.listdir(base)
                if len(a) == 2
                for b in os.listdir(os.path.join(base, a))
            ]
    for candidate in candidates:
        try:
            _checked_prefix(candidate, root=root)
        except Exception:
            failures.append(candidate)
    return failures


def reachable(root: str) -> set[str]:
    found = set()
    import re

    for base, _, files in os.walk(root):
        if "/objects/" in base or "/metadata/" in base:
            continue
        for name in files:
            try:
                data = open(os.path.join(base, name), "rb").read().decode("utf-8", "ignore")
            except OSError:
                continue
            found.update(re.findall(r"sha256:[0-9a-f]{64}", data))
    # ``run.json`` is solve-owned and deliberately sits beside .rat; it is a
    # root reference even though it is outside the object-store directory.
    try:
        data = open(os.path.join(os.path.dirname(os.path.abspath(root)), "run.json"), "rb").read().decode("utf-8", "ignore")
        found.update(re.findall(r"sha256:[0-9a-f]{64}", data))
    except OSError:
        pass
    return found


def gc(*, root: str | None = None, dry_run=True) -> list[str]:
    root = _root(root)
    keep = reachable(root)
    removed = []
    base = os.path.join(root, "objects", "sha256")
    if not os.path.isdir(base):
        return removed
    for a in os.listdir(base):
        for b in os.listdir(os.path.join(base, a)):
            digest = "sha256:" + a + b
            if digest not in keep:
                removed.append(digest)
                if not dry_run:
                    obj, meta = _paths(root, digest)
                    os.unlink(obj)
                    if os.path.exists(meta):
                        os.unlink(meta)
    return removed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root")
    sub = parser.add_subparsers(dest="cmd", required=True)
    command = sub.add_parser("put")
    command.add_argument("file")
    command.add_argument("--kind", required=True)
    command.add_argument("--media-type", required=True)
    command.add_argument("--logical-name")
    command = sub.add_parser("get")
    command.add_argument("digest")
    command.add_argument("--output")
    command = sub.add_parser("verify")
    command.add_argument("digest", nargs="?")
    command = sub.add_parser("gc")
    command.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.cmd == "put":
        print(json.dumps(put_file(
            args.file,
            kind=args.kind,
            media_type=args.media_type,
            logical_name=args.logical_name or os.path.basename(args.file),
            root=args.root,
        )))
    elif args.cmd == "get":
        data = get(args.digest, root=args.root)
        if args.output:
            open(args.output, "wb").write(data)
        else:
            os.write(1, data)
    elif args.cmd == "verify":
        bad = verify(args.digest, root=args.root)
        print(json.dumps({"ok": not bad, "failures": bad}))
        raise SystemExit(1 if bad else 0)
    else:
        print(json.dumps({"dry_run": not args.apply, "objects": gc(root=args.root, dry_run=not args.apply)}))


if __name__ == "__main__":
    main()
