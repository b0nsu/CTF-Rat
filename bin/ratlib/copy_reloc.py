"""Shared static ELF COPY-relocation scan (readelf-backed, bounded).

An unsupported or unparseable scan is reported as a warning, never as
"no COPY relocations", so callers cannot silently treat an unknown result as a
clean one. Used by both ``libcgate`` (triage view) and ``rat query pwn``
(attention facts) so the stdout/stdin/stderr copy facts stay consistent.
"""
import os
import re
import shutil
import subprocess
import tempfile

_COPY_KINDS = {3: "R_386_COPY", 62: "R_X86_64_COPY", 183: "R_AARCH64_COPY"}


def copy_relocations(binary):
    """Return (list_of_(addr_str, symbol, kind), None) or (None, warning).

    addr_str is ``PIE+0x..`` for ET_DYN, ``0x..`` otherwise.
    """
    try:
        with open(binary, "rb") as fh:
            header = fh.read(20)
    except OSError as exc:
        return None, "cannot read ELF header (%s)" % type(exc).__name__
    if header[:4] != b"\x7fELF" or len(header) < 20:
        return None, "selected artifact is not an ELF executable"
    endian = "little" if header[5] == 1 else "big" if header[5] == 2 else None
    if endian is None:
        return None, "ELF byte order is unknown"
    e_type = int.from_bytes(header[16:18], endian)
    machine = int.from_bytes(header[18:20], endian)
    if machine not in _COPY_KINDS:
        return None, "ELF machine %d has no supported COPY relocation parser" % machine
    readelf = shutil.which("readelf")
    if not readelf:
        return None, "readelf unavailable; COPY relocation scan not performed"
    try:
        with tempfile.TemporaryFile() as capture:
            result = subprocess.run([readelf, "-rW", "--", binary],
                                    stdout=capture, stderr=capture, timeout=10, check=False,
                                    env={**os.environ, "LC_ALL": "C"})
            if result.returncode:
                return None, "readelf failed (exit %d)" % result.returncode
            if capture.tell() > 2 * 1024 * 1024:
                return None, "readelf relocation output exceeds 2 MiB bound"
            capture.seek(0)
            output = capture.read().decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "readelf unavailable or timed out (%s)" % type(exc).__name__
    sections = re.findall(r"^Relocation section '([^']+)' at offset 0x[0-9a-fA-F]+ "
                          r"contains ([0-9]+) entr(?:y|ies):$", output, re.M)
    no_relocations = re.search(r"^There are no relocations in this file\.$", output, re.M)
    if not sections and not no_relocations:
        return None, "readelf relocation output is unrecognized"
    expected_rows = sum(int(count) for name, count in sections if not name.startswith(".relr"))
    parsed_rows = sum(bool(re.match(r"^[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\S+", line))
                      for line in output.splitlines())
    if parsed_rows < expected_rows:
        return None, "readelf relocation output is incomplete"
    copies = set()
    for line in output.splitlines():
        fields = line.split()
        if (len(fields) < 5 or not re.fullmatch(r"[0-9a-fA-F]+", fields[0])
                or fields[2] != _COPY_KINDS[machine]):
            continue
        symbol = fields[4].split("@", 1)[0]
        if symbol:
            copies.add((int(fields[0], 16), symbol, fields[2]))
    return [(("PIE+0x%x" if e_type == 3 else "0x%x") % addr, symbol, kind)
            for addr, symbol, kind in sorted(copies)], None
