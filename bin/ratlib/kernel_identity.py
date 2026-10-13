"""Bounded, dependency-free Linux image identity and ELF symbol metadata.

No filename/string heuristics, execution, decompression or CFG recovery.
Executable NOTYPE symbols are retained for kallsyms-reconstructed ELFs.
"""
from __future__ import annotations

import os
import struct

MAX_SECTIONS = 4096
MAX_TABLE_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_SYMBOLS = 250000
SCHEMA = "rat.kernel-identity/v1"
KERNEL_SECTIONS = {".init.text", ".init.data", ".data..percpu", "__ksymtab",
                   "__ksymtab_gpl", ".ksymtab", ".altinstructions", ".orc_unwind"}
KERNEL_SYMBOLS = {"start_kernel", "copy_process", "init_task", "linux_banner",
                  "prepare_kernel_cred", "commit_creds", "kallsyms_lookup_name"}


def inspect(path, *, include_symbols=False):
    result = {"schema": SCHEMA, "kind": "unknown", "path": os.path.abspath(path), "sections": [], "kernel_symbols": [],
              "diagnostics": [], "symbols_truncated": False}
    with open(path, "rb") as source:
        size = os.fstat(source.fileno()).st_size
        bytes_read = 0

        def read(offset, length):
            nonlocal bytes_read
            if (offset < 0 or length < 0 or offset + length > size
                    or length > MAX_TABLE_BYTES or bytes_read + length > MAX_METADATA_BYTES):
                raise ValueError("ELF metadata range exceeds file or bounded table budget")
            bytes_read += length
            source.seek(offset)
            data = source.read(length)
            if len(data) != length:
                raise ValueError("truncated ELF metadata")
            return data

        header = source.read(0x240)
        if (len(header) >= 0x212 and header[0x1fe:0x200] == b"\x55\xaa"
                and header[0x202:0x206] == b"HdrS"
                and int.from_bytes(header[0x206:0x208], "little") >= 0x200):
            result.update(kind="bzimage" if header[0x211] & 1 else "linux-boot-image",
                          protocol=int.from_bytes(header[0x206:0x208], "little"))
            return result
        if header[:4] != b"\x7fELF":
            return result
        result["kind"] = "elf"
        try:
            if len(header) < 52 or header[4] not in (1, 2) or header[5] not in (1, 2):
                raise ValueError("unsupported or truncated ELF header")
            endian = "<" if header[5] == 1 else ">"
            elf64 = header[4] == 2
            fmt = endian + ("HHIQQQIHHHHHH" if elf64 else "HHIIIIIHHHHHH")
            values = struct.unpack(fmt, read(16, struct.calcsize(fmt)))
            etype, machine, _, entry, _, shoff, _, _, _, _, shentsize, shnum, shstr = values
            result.update(elf_type=etype, machine=machine, entry=entry)
            shfmt = endian + ("IIQQQQIIQQ" if elf64 else "IIIIIIIIII")
            shsize = struct.calcsize(shfmt)
            if not shoff:
                return result
            if shentsize < shsize:
                raise ValueError("invalid ELF section entry size")
            # ELF extended numbering is stored in section zero.
            zero = struct.unpack(shfmt, read(shoff, shsize))
            shnum = shnum or zero[5]
            shstr = zero[6] if shstr == 0xffff else shstr
            if not 0 < shnum <= MAX_SECTIONS or shstr >= shnum:
                raise ValueError("ELF section count exceeds bounded metadata budget")
            raw_sections = read(shoff, shentsize * shnum)
            sections = [struct.unpack_from(shfmt, raw_sections, i * shentsize) for i in range(shnum)]
            names_section = sections[shstr]
            names = read(names_section[4], names_section[5])

            def cstring(table, offset):
                if offset >= len(table):
                    raise ValueError("invalid ELF string offset")
                end = table.find(b"\0", offset, min(len(table), offset + 4096))
                if end < 0:
                    raise ValueError("unterminated ELF metadata string")
                return table[offset:end].decode("utf-8", errors="replace")

            section_names = [cstring(names, s[0]) for s in sections]
            result["sections"] = sorted(KERNEL_SECTIONS & set(section_names))
            anchors, functions, seen = set(), [], set()
            remaining = MAX_SYMBOLS
            symfmt = endian + ("IBBHQQ" if elf64 else "IIIBBH")
            symsize = struct.calcsize(symfmt)
            for section in sections:
                if section[1] not in (2, 11):
                    continue
                if section[6] >= len(sections) or section[9] < symsize:
                    raise ValueError("invalid ELF symbol table")
                strsec = sections[section[6]]
                strings = read(strsec[4], strsec[5])
                total = section[5] // section[9]
                count = min(total, remaining)
                # Never allocate/read an unbounded symbol table.
                count = min(count, MAX_TABLE_BYTES // section[9])
                raw = read(section[4], count * section[9])
                result["symbols_truncated"] |= count < total
                remaining -= count
                for i in range(count):
                    fields = struct.unpack_from(symfmt, raw, i * section[9])
                    if elf64:
                        nameoff, info, _, secidx, value, symsz = fields
                    else:
                        nameoff, value, symsz, info, _, secidx = fields
                    if not nameoff or not 0 < secidx < len(sections):
                        continue
                    name = cstring(strings, nameoff)
                    if name in KERNEL_SYMBOLS:
                        anchors.add(name)
                    if (include_symbols and (info & 15) in (0, 2)
                            and sections[secidx][2] & 4 and (name, value) not in seen):
                        seen.add((name, value))
                        functions.append({"name": name, "addr": value, "size": symsz,
                                          "symbol_type": "func" if (info & 15) == 2 else "notype"})
            result["kernel_symbols"] = sorted(anchors)
            # vmlinux-to-elf style recovery may have only a single executable
            # .text section. Multiple core anchors plus kernel-space VMAs are
            # structural corroboration in that case; names alone are not.
            threshold = {62:0xffffffff80000000,3:0xc0000000,183:0xffff000000000000}.get(machine)
            high_text = threshold is not None and any(
                (s[2] & 6) == 6 and s[3] >= threshold for s in sections)
            result["high_kernel_text"] = high_text
            if etype == 2 and ((result["sections"] and len(anchors) >= 2)
                              or (high_text and len(anchors) >= 3)):
                result["kind"] = "vmlinux"
            if include_symbols:
                result["functions"] = functions
        except (ValueError, struct.error) as exc:
            result["diagnostics"].append(str(exc))
    return result
