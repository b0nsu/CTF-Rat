"""Explicit raw-code loading and bounded boot/disk identity hints.

A boot signature is *not* sufficient evidence of architecture or executable
mapping. Never feed disk images into CFGFast without a caller-provided load spec.
"""
from __future__ import annotations

import os
import re


_ARCH = {
    "i386": "X86", "x86": "X86", "amd64": "AMD64",
    "x86_64": "AMD64", "aarch64": "AARCH64", "arm": "ARMEL",
}


def inspect_raw(path):
    """Return tentative, metadata-only format hints without executing content."""
    size = os.path.getsize(path)
    with open(path, "rb") as stream:
        head = stream.read(512)
    result = {"kind": "unknown", "size": size}
    if head.startswith((b"\x7fELF", b"MZ")) or head[:4] in (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    ):
        return result
    boot_sig = len(head) == 512 and head[510:512] == b"\x55\xaa"
    fat_bpb = boot_sig and (head[54:57] == b"FAT" or head[82:85] == b"FAT")
    floppy_size = size in (360 * 1024, 720 * 1024, 1200 * 1024, 1440 * 1024, 2880 * 1024)
    if fat_bpb or floppy_size:
        result["kind"] = "disk-image-candidate"
    elif boot_sig:
        result["kind"] = "boot-sector-candidate"
    if result["kind"] != "unknown":
        result.update(boot_signature=boot_sig, sector_aligned=(size % 512 == 0),
                      fat_bpb_candidate=fat_bpb)
    return result


def load_spec(path, *, arch=None, base=None, entry=None):
    """Normalize explicit blob hints; never infer an ISA from a boot signature."""
    if arch is None and base is None and entry is None:
        return None
    if arch is None or base is None or entry is None:
        raise ValueError("raw code requires --arch, --base and --entry together")
    normalized = _ARCH.get(str(arch).lower())
    if normalized is None:
        raise ValueError("unsupported blob arch: %s" % arch)
    def address(value):
        if isinstance(value, int):
            return value
        if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", value):
            raise ValueError("invalid blob address: %r" % value)
        return int(value, 0) if value.lower().startswith("0x") else int(value, 10)
    base_addr, entry_addr = address(base), address(entry)
    size = os.path.getsize(path)
    if size == 0 or base_addr < 0 or not base_addr <= entry_addr < base_addr + size:
        raise ValueError("blob entry must be within the mapped raw file")
    return {"backend": "blob", "arch": normalized,
            "base_addr": base_addr, "entry_point": entry_addr}


def project(path, spec):
    """Single angr project adapter, used by revq and future bounded analyses."""
    import angr
    if spec is None:
        return angr.Project(path, auto_load_libs=False)
    import archinfo
    opts = dict(spec)
    opts["arch"] = archinfo.arch_from_id(spec["arch"])
    return angr.Project(path, auto_load_libs=False, main_opts=opts)
