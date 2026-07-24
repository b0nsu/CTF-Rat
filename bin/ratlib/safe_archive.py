"""Fail-closed ZIP/TAR extraction for untrusted CTF attachments."""
from __future__ import annotations

import os
import json
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable, Tuple


class ArchiveError(ValueError):
    """The archive is unsupported, malformed, or violates extraction policy."""


@dataclass(frozen=True)
class ArchivePolicy:
    max_members: int = 4096
    max_member_bytes: int = 256 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_compression_ratio: int = 100
    max_path_bytes: int = 4096
    max_component_bytes: int = 240
    max_depth: int = 2


DEFAULT_POLICY = ArchivePolicy()


def load_policy(path: str) -> ArchivePolicy:
    """Load a JSON policy that may only tighten the built-in limits."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as exc:
        raise ArchiveError("cannot read archive policy: %s" % exc) from exc
    allowed = set(ArchivePolicy.__dataclass_fields__)
    unknown = set(raw) - allowed if isinstance(raw, dict) else {"<not-object>"}
    if unknown:
        raise ArchiveError("unknown archive policy field(s): %s" % ", ".join(sorted(unknown)))
    values = {name: getattr(DEFAULT_POLICY, name) for name in allowed}
    for name, value in raw.items():
        if not isinstance(value, int) or value <= 0 or value > values[name]:
            raise ArchiveError("archive policy may only lower positive limit %s" % name)
        values[name] = value
    return ArchivePolicy(**values)


def _normal_member_name(name: str, policy: ArchivePolicy) -> str:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ArchiveError("archive member has an empty or NUL-containing name")
    raw = name.replace("\\", "/")
    if raw.startswith("/") or raw.startswith("//") or re.match(r"^[A-Za-z]:", raw):
        raise ArchiveError("archive member uses an absolute path: %r" % name)
    stripped = raw.rstrip("/")
    if not stripped:
        raise ArchiveError("archive member has no destination path")
    parts = stripped.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ArchiveError("archive member escapes its root: %r" % name)
    path = PurePosixPath(stripped)
    encoded = str(path).encode("utf-8", "surrogatepass")
    if len(encoded) > policy.max_path_bytes:
        raise ArchiveError("archive member path is too long: %r" % name)
    if any(len(part.encode("utf-8", "surrogatepass")) > policy.max_component_bytes for part in path.parts):
        raise ArchiveError("archive member path component is too long: %r" % name)
    return str(path)


def _check_limits(members: Iterable[Tuple[str, int, int]], policy: ArchivePolicy) -> None:
    checked = list(members)
    if len(checked) > policy.max_members:
        raise ArchiveError("archive has too many members (%d > %d)" % (len(checked), policy.max_members))
    total, seen = 0, set()
    for name, size, compressed in checked:
        if name in seen:
            raise ArchiveError("archive has duplicate destination: %s" % name)
        seen.add(name)
        if size < 0 or size > policy.max_member_bytes:
            raise ArchiveError("archive member exceeds size limit: %s" % name)
        total += size
        if total > policy.max_total_bytes:
            raise ArchiveError("archive exceeds total uncompressed size limit")
        if size and compressed >= 0 and compressed == 0:
            raise ArchiveError("archive member has invalid compressed size: %s" % name)
        if size and compressed > 0 and size > compressed * policy.max_compression_ratio:
            raise ArchiveError("archive member exceeds compression ratio limit: %s" % name)


def _zip_members(zf: zipfile.ZipFile, policy: ArchivePolicy):
    out, limits = [], []
    for info in zf.infolist():
        name = _normal_member_name(info.filename, policy)
        mode = (info.external_attr >> 16) & 0o170000
        if mode and mode not in (stat.S_IFREG, stat.S_IFDIR):
            raise ArchiveError("archive member is not a regular file/directory: %s" % info.filename)
        limits.append((name, 0 if info.is_dir() else info.file_size, 0 if info.is_dir() else info.compress_size))
        out.append((info, name))
    _check_limits(limits, policy)
    return out


def _tar_members(tf: tarfile.TarFile, policy: ArchivePolicy):
    out, limits = [], []
    for member in tf.getmembers():
        name = _normal_member_name(member.name, policy)
        if not (member.isfile() or member.isdir()):
            raise ArchiveError("archive member is not a regular file/directory: %s" % member.name)
        limits.append((name, member.size if member.isfile() else 0, -1))
        out.append((member, name))
    _check_limits(limits, policy)
    return out


def _target(root: str, relative: str) -> str:
    path = os.path.abspath(os.path.join(root, *PurePosixPath(relative).parts))
    if os.path.commonpath((root, path)) != root:
        raise ArchiveError("archive member escapes extraction root: %s" % relative)
    return path


def _copy_stream(source, destination: str, expected: int, policy: ArchivePolicy) -> None:
    written = 0
    with open(destination, "xb") as dst:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > expected or written > policy.max_member_bytes:
                raise ArchiveError("archive member expands beyond declared size")
            dst.write(chunk)
    if written != expected:
        raise ArchiveError("archive member size does not match header")


def _extract_zip(zf, members, root: str, policy: ArchivePolicy) -> None:
    for info, name in members:
        dest = _target(root, name)
        if info.is_dir():
            os.makedirs(dest, mode=0o700, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        with zf.open(info, "r") as source:
            _copy_stream(source, dest, info.file_size, policy)
        mode = (info.external_attr >> 16) & 0o777
        os.chmod(dest, 0o700 if mode & 0o111 else 0o600)


def _extract_tar(tf, members, root: str, policy: ArchivePolicy) -> None:
    for member, name in members:
        dest = _target(root, name)
        if member.isdir():
            os.makedirs(dest, mode=0o700, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        source = tf.extractfile(member)
        if source is None:
            raise ArchiveError("cannot read archive member: %s" % member.name)
        with source:
            _copy_stream(source, dest, member.size, policy)
        os.chmod(dest, 0o700 if member.mode & 0o111 else 0o600)


def _merge_tree(source: str, destination: str) -> None:
    entries = sorted(os.listdir(source))
    collisions = [entry for entry in entries if os.path.lexists(os.path.join(destination, entry))]
    if collisions:
        raise ArchiveError("extraction would overwrite existing path(s): %s" % ", ".join(collisions))
    for entry in entries:
        os.replace(os.path.join(source, entry), os.path.join(destination, entry))


def safe_extract_archive(archive_path: str, destination: str, policy: ArchivePolicy = DEFAULT_POLICY) -> int:
    """Extract one ZIP/TAR archive or raise without touching destination content."""
    archive_path, destination = os.path.abspath(archive_path), os.path.abspath(destination)
    if not os.path.isfile(archive_path):
        raise ArchiveError("archive does not exist: %s" % archive_path)
    os.makedirs(destination, mode=0o700, exist_ok=True)
    temp = tempfile.mkdtemp(prefix=".ctfpull-extract-", dir=destination)
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as zf:
                members = _zip_members(zf, policy)
                _extract_zip(zf, members, temp, policy)
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as tf:
                members = _tar_members(tf, policy)
                _extract_tar(tf, members, temp, policy)
        else:
            raise ArchiveError("unsupported archive format: %s" % os.path.basename(archive_path))
        _merge_tree(temp, destination)
        return len(members)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise ArchiveError("archive extraction failed: %s" % exc) from exc
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def is_supported_archive(path: str) -> bool:
    try:
        return zipfile.is_zipfile(path) or tarfile.is_tarfile(path)
    except OSError:
        return False
