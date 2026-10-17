"""Bounded WebAssembly core-module inventory; this is not a Wasm interpreter."""
from __future__ import annotations

import hashlib

MAGIC = b"\0asm\x01\0\0\0"
MAX_MODULE = 64 * 1024 * 1024
MAX_ITEMS = 4096


def is_wasm(path):
    with open(path, "rb") as fh:
        return fh.read(4) == MAGIC[:4]


def _u32(data, pos):
    value = 0
    for shift in range(0, 35, 7):
        if pos >= len(data):
            raise ValueError("truncated LEB128 integer")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            if value > 0xffffffff:
                raise ValueError("LEB128 integer exceeds u32")
            return value, pos
    raise ValueError("overlong LEB128 integer")


def _name(data, pos):
    length, pos = _u32(data, pos)
    end = pos + length
    if end > len(data) or length > 4096:
        raise ValueError("truncated or oversized Wasm name")
    return data[pos:end].decode("utf-8", "replace"), end


def _vector_count(data):
    count, pos = _u32(data, 0)
    if count > MAX_ITEMS:
        raise ValueError("Wasm vector exceeds bounded inventory")
    return count, pos


def inspect(path):
    with open(path, "rb") as fh:
        data = fh.read(MAX_MODULE + 1)
    if len(data) > MAX_MODULE:
        raise ValueError("Wasm module exceeds 64 MiB inventory limit")
    if not data.startswith(MAGIC):
        raise ValueError("unsupported WebAssembly header (core module v1 required)")
    sections, exports, functions, imports = [], [], [], []
    imported_functions = 0
    pos = len(MAGIC)
    while pos < len(data):
        section_id = data[pos]
        pos += 1
        size, pos = _u32(data, pos)
        end = pos + size
        if end > len(data):
            raise ValueError("truncated Wasm section")
        payload = data[pos:end]
        sections.append({"id": section_id, "size": size, "offset": pos})
        if len(sections) > 128:
            raise ValueError("too many Wasm sections")
        if section_id == 2:
            count, cursor = _vector_count(payload)
            for _ in range(count):
                module, cursor = _name(payload, cursor)
                name, cursor = _name(payload, cursor)
                if cursor >= len(payload):
                    raise ValueError("truncated Wasm import")
                kind = payload[cursor]
                cursor += 1
                if kind == 0:  # function type index
                    _, cursor = _u32(payload, cursor)
                    imported_functions += 1
                elif kind == 1:  # table type
                    cursor = _skip_table(payload, cursor)
                elif kind == 2:  # memory limits
                    cursor = _skip_limits(payload, cursor)
                elif kind == 3:  # global type
                    cursor += 2
                else:
                    raise ValueError("unsupported Wasm import kind %d" % kind)
                if cursor > len(payload):
                    raise ValueError("truncated Wasm import type")
                imports.append({"module": module, "name": name, "kind": kind})
        elif section_id == 7:
            count, cursor = _vector_count(payload)
            for _ in range(count):
                name, cursor = _name(payload, cursor)
                if cursor >= len(payload):
                    raise ValueError("truncated Wasm export")
                kind = payload[cursor]
                index, cursor = _u32(payload, cursor + 1)
                exports.append({"name": name, "kind": kind, "index": index})
        elif section_id == 10:
            count, cursor = _vector_count(payload)
            for index in range(count):
                size_body, cursor = _u32(payload, cursor)
                body_end = cursor + size_body
                if body_end > len(payload):
                    raise ValueError("truncated Wasm function body")
                body = payload[cursor:body_end]
                functions.append({"index": imported_functions + index,
                                  "size": size_body,
                                  "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest()})
                cursor = body_end
        pos = end
    names = {e["index"]: e["name"] for e in exports if e["kind"] == 0}
    for func in functions:
        func["name"] = names.get(func["index"], "func_%d" % func["index"])
    return {"schema": "rat.wasm-inventory/v1", "format": "wasm-core-v1",
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            "sections": sections, "imports": imports, "exports": exports,
            "functions": functions, "imported_functions": imported_functions,
            "coverage": "section-and-body-inventory-only"}


def _skip_limits(data, pos):
    flags, pos = _u32(data, pos)
    if flags & ~3:
        raise ValueError("unsupported Wasm memory/table limit flags")
    _, pos = _u32(data, pos)
    if flags & 1:
        _, pos = _u32(data, pos)
    return pos


def _skip_table(data, pos):
    if pos >= len(data):
        raise ValueError("truncated Wasm table type")
    return _skip_limits(data, pos + 1)
