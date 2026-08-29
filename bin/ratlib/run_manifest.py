"""Validation and atomic ownership transfer for ``rat.run/v1`` manifests."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


SCHEMA = "rat.run/v1"
VALID_STATUS = {"created", "active", "blocked", "verified", "complete"}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def environment_identity() -> dict[str, str]:
    """Canonical runtime identity shared by run manifests and benchmarks."""
    return {"os": os.sys.platform, "arch": platform.machine() or "unknown",
            "runtime": "python-%d.%d" % os.sys.version_info[:2]}


def ctf_rat_revision(root: Optional[str] = None) -> str:
    """Resolve a reproducible CTF-Rat revision without making git mandatory.

    Explicit ``CTF_RAT_REVISION`` wins.  Benchmark callers may then supply the
    repository root so a normal git checkout records HEAD.  Exported/runtime
    copies without git metadata preserve the historical ``worktree`` fallback.
    """
    explicit = os.environ.get("CTF_RAT_REVISION")
    if explicit:
        return explicit
    if root:
        try:
            proc = subprocess.run(
                ["git", "-C", os.path.abspath(root), "rev-parse", "HEAD"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5, text=True,
            )
            revision = proc.stdout.strip()
            if re.fullmatch(r"[0-9a-fA-F]{40}", revision):
                revision = revision.lower()
                diff = subprocess.run(
                    ["git", "-C", os.path.abspath(root), "diff", "--binary", "HEAD", "--"],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=10,
                ).stdout
                untracked = subprocess.run(
                    ["git", "-C", os.path.abspath(root), "ls-files", "--others",
                     "--exclude-standard", "-z"],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=10,
                ).stdout
                if not diff and not untracked:
                    return revision
                dirty = hashlib.sha256()
                dirty.update(diff)
                for relative in sorted(path for path in untracked.split(b"\0") if path):
                    dirty.update(relative + b"\0")
                    path = os.path.join(os.path.abspath(root), os.fsdecode(relative))
                    try:
                        dirty.update(os.fsencode(sha256_file(path)))
                    except OSError:
                        dirty.update(b"unreadable")
                return revision + "+dirty.sha256:" + dirty.hexdigest()
        except (OSError, subprocess.SubprocessError):
            pass
    return "worktree"


def toolchain_identity(root: Optional[str] = None) -> dict[str, str]:
    return {"ctf_rat_revision": ctf_rat_revision(root), "schema_bundle": "v1"}


def validate(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    required = ("schema", "run_id", "created_at", "updated_at", "challenge", "status",
                "inputs", "target_policy", "environment", "toolchain", "policy")
    missing = [key for key in required if key not in manifest]
    if missing:
        raise ValueError("run manifest missing required fields: %s" % ", ".join(missing))
    if manifest["schema"] != SCHEMA or manifest["status"] not in VALID_STATUS:
        raise ValueError("run manifest schema/status is invalid")
    if not isinstance(manifest["run_id"], str) or len(manifest["run_id"]) < 8:
        raise ValueError("run manifest run_id is invalid")
    challenge = manifest["challenge"]
    if not isinstance(challenge, Mapping) or not isinstance(challenge.get("name"), str):
        raise ValueError("run manifest challenge is invalid")
    if not isinstance(manifest["inputs"], list):
        raise ValueError("run manifest inputs must be an array")
    for item in manifest["inputs"]:
        if not isinstance(item, Mapping) or not _DIGEST.fullmatch(str(item.get("sha256", ""))):
            raise ValueError("run manifest input digest is invalid")
        if not isinstance(item.get("size"), int) or item["size"] < 0:
            raise ValueError("run manifest input size is invalid")
    return manifest


def atomic_write(path: str, manifest: Mapping[str, Any]) -> None:
    validate(manifest)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".run-", suffix=".json.tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(manifest, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as source:
        payload = json.load(source)
    validate(payload)
    return payload


def _input(role: str, path: str, name: Optional[str] = None) -> dict[str, Any]:
    return {"role": role, "name": name or os.path.basename(path),
            "sha256": sha256_file(path), "size": os.path.getsize(path)}


def new_direct(name: str, binary: str, libc: Optional[str], remote: Optional[str]) -> dict[str, Any]:
    timestamp = now_iso()
    inputs = [_input("binary", binary)]
    if libc:
        inputs.append(_input("libc", libc, "libc.so.6"))
    toolchain = toolchain_identity()
    toolchain["newchal_version"] = "p0-v1"
    return {
        "schema": SCHEMA,
        "run_id": "run_" + uuid.uuid4().hex,
        "created_at": timestamp,
        "updated_at": timestamp,
        "challenge": {"id": None, "name": name, "category": None},
        "status": "created",
        "inputs": inputs,
        "target_policy": {"guard_challenge": name, "allowlist": [remote] if remote else [],
                          "network_mode": "ctfguard-target" if remote else "none"},
        "environment": environment_identity(),
        "toolchain": toolchain,
        "policy": {"archive": {}, "subprocess": {"wall_timeout_seconds": 60,
                                                   "output_hard_cap_bytes": 64 * 1024 * 1024}},
        "state": {"stream_id": None, "latest_event_cursor": None, "latest_checkpoint_id": None},
    }


def materialize_for_solve(source: Optional[str], destination: str, *, name: str,
                          binary: str, libc: Optional[str], remote: Optional[str],
                          owner_path: str) -> dict[str, Any]:
    """Preserve one run identity while making solve/run.json the authoritative copy."""
    incoming = read(source) if source else None
    existing = read(destination) if os.path.isfile(destination) else None
    if incoming and existing and incoming["run_id"] != existing["run_id"]:
        raise ValueError("refusing to replace solve manifest with a different run_id")
    if incoming and existing:
        payload = copy.deepcopy(incoming)
        payload.update(existing)  # solve-owned lifecycle/custom fields are newer
        payload["run_id"] = incoming["run_id"]
        payload["created_at"] = incoming["created_at"]
    else:
        payload = incoming or existing or new_direct(name, binary, libc, remote)
    payload = copy.deepcopy(payload)
    inputs = [item for item in payload["inputs"] if item.get("role") not in ("binary", "libc")]
    inputs.append(_input("binary", binary))
    if libc:
        inputs.append(_input("libc", libc, "libc.so.6"))
    payload["inputs"] = inputs
    payload["updated_at"] = now_iso()
    payload["manifest_owner"] = {"kind": "solve", "path": owner_path}
    payload["scaffold"] = {"name": name, "binary": os.path.basename(binary),
                           "libc": "libc.so.6" if libc else None}
    payload.setdefault("target_policy", {})["guard_challenge"] = name
    if remote:
        payload["target_policy"]["allowlist"] = [remote]
        payload["target_policy"]["network_mode"] = "ctfguard-target"
    payload.setdefault("toolchain", {})["newchal_version"] = "p0-v1"
    atomic_write(destination, payload)
    return payload
