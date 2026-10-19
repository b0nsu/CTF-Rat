"""Resolve a decomp request against the exported Ghidra index.

The index and export metadata describe Ghidra addresses.  Only ELF ET_DYN
requests may need translation from revq/angr's 0x400000 load base.
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys


ANGR_PIE_BASE = 0x400000
ADDRESS = re.compile(r"^(?:(sub_|FUN_))?(?:0[xX])?([0-9a-fA-F]+)$")


def binary_kind(path: str) -> str:
    with open(path, "rb") as stream:
        header = stream.read(64)
        if header[:2] == b"MZ" and len(header) >= 64:
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if 64 <= pe_offset <= os.path.getsize(path) - 4:
                stream.seek(pe_offset)
                if stream.read(4) == b"PE\0\0":
                    return "pe"
    if header[:4] == b"\x7fELF" and len(header) >= 18:
        endian = "<" if header[5] == 1 else ">" if header[5] == 2 else None
        if endian:
            elf_type = struct.unpack_from(endian + "H", header, 16)[0]
            return "elf-pie" if elf_type == 3 else "elf"
    return "unknown"


def image_base(cache: str) -> int | None:
    try:
        with open(os.path.join(cache, ".rat-decomp-status.json"), encoding="utf-8") as stream:
            value = json.load(stream).get("image_base")
        if isinstance(value, str) and re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", value):
            return int(value, 16)
    except (OSError, ValueError, TypeError):
        pass
    return None


def _rows(cache: str):
    with open(os.path.join(cache, "_index.txt"), encoding="utf-8", errors="replace") as stream:
        for line in stream:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            try:
                address = int(parts[0], 16)
            except ValueError:
                continue
            name = parts[1]
            file_names = []
            if len(parts) >= 4:
                file_names.append(parts[3] + ".c")
            file_names.extend((f"{parts[0]}_{name}.c", name + ".c"))
            for file_name in file_names:
                if os.path.basename(file_name) != file_name:
                    continue
                path = os.path.join(cache, file_name)
                if os.path.isfile(path):
                    yield address, name, path
                    break


def resolve(binary: str, cache: str, request: str) -> tuple[str, str, str, str]:
    """Return status, cached path, Ghidra address, objdump file VMA."""
    rows = list(_rows(cache))
    for _, name, path in rows:
        if request == name or request + ".c" == os.path.basename(path):
            return "hit", path, "-", "-"
    direct = os.path.join(cache, request + ".c")
    if os.path.isfile(direct) and os.path.basename(direct) == request + ".c":
        return "hit", direct, "-", "-"

    match = ADDRESS.fullmatch(request)
    if not match:
        return "unknown", "-", "-", "-"
    spelling, digits = match.groups()
    address = int(digits, 16)
    kind = binary_kind(binary)
    base = image_base(cache)
    candidates = [address]
    if kind == "elf-pie" and base is not None and spelling != "FUN_":
        if address >= ANGR_PIE_BASE:
            candidates.append(address - ANGR_PIE_BASE + base)
        elif spelling is None:
            # A small numeric address can be an ELF VMA.  A sub_ name is an
            # angr address and should never be interpreted as a file VMA.
            candidates.append(address + base)

    for candidate in dict.fromkeys(candidates):
        for row_address, _, path in rows:
            if row_address == candidate:
                return "hit", path, "-", "-"

    # FUN_ names already denote Ghidra addresses.  Other PIE addresses need
    # the observed image base before a one-shot import can safely target them.
    if kind == "elf-pie" and spelling != "FUN_" and base is None:
        return "unknown", "-", "-", "-"
    target = candidates[-1]
    file_vma = target - base if kind == "elf-pie" and base is not None else target
    return "miss", "-", format(target, "x"), format(file_vma, "x")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: decomp_lookup.py BIN CACHE FUNC")
    print("\t".join(resolve(*sys.argv[1:])))
