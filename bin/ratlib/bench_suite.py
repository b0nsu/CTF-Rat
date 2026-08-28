"""Small fail-closed validator for ratbench suite manifests.

This is intentionally not a new schema subsystem.  ``bench/suite.json`` is the
canonical manifest and this module validates only the fields ratbench needs to
compare synthetic, integration, real, and private/held-out corpora safely.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping

SCHEMA = "rat.bench-suite/v1"
CORPORA = {"synthetic", "integration", "real", "private"}
TRACKS = {"pwn", "rev"}
VERIFY_KINDS = {"flag-regex", "symsolve-restore", "rat-verify-pass"}
_CAPABILITY = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class SuiteValidationError(ValueError):
    pass


def _relative_path(value, field, entry_id):
    if not isinstance(value, str) or not value or os.path.isabs(value):
        raise SuiteValidationError("%s.%s must be a non-empty relative path" % (entry_id, field))
    normalized = os.path.normpath(value)
    if normalized in ("", ".", os.pardir) or normalized.startswith(os.pardir + os.sep):
        raise SuiteValidationError("%s.%s escapes the suite root" % (entry_id, field))
    return normalized


def validate_suite(doc):
    if not isinstance(doc, Mapping):
        raise SuiteValidationError("suite must be an object")
    if doc.get("schema") != SCHEMA:
        raise SuiteValidationError("unsupported suite schema")
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        raise SuiteValidationError("suite.entries must be a non-empty list")

    seen = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise SuiteValidationError("suite entry must be an object")
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not _CAPABILITY.fullmatch(entry_id):
            raise SuiteValidationError("invalid benchmark entry id")
        if entry_id in seen:
            raise SuiteValidationError("duplicate benchmark entry id: %s" % entry_id)
        seen.add(entry_id)

        if entry.get("track") not in TRACKS:
            raise SuiteValidationError("%s.track must be pwn or rev" % entry_id)
        if not isinstance(entry.get("expected_route"), str) or not entry["expected_route"]:
            raise SuiteValidationError("%s.expected_route is required" % entry_id)
        difficulty = entry.get("difficulty")
        if not isinstance(difficulty, int) or isinstance(difficulty, bool) or difficulty < 1:
            raise SuiteValidationError("%s.difficulty must be a positive integer" % entry_id)

        corpus = entry.get("corpus")
        if corpus not in CORPORA:
            raise SuiteValidationError("%s.corpus must be one of %s" % (entry_id, sorted(CORPORA)))
        if not isinstance(entry.get("redistributable"), bool):
            raise SuiteValidationError("%s.redistributable must be boolean" % entry_id)
        capabilities = entry.get("capabilities")
        if (not isinstance(capabilities, list) or not capabilities
                or any(not isinstance(tag, str) or not _CAPABILITY.fullmatch(tag) for tag in capabilities)
                or len(capabilities) != len(set(capabilities))):
            raise SuiteValidationError("%s.capabilities must be a non-empty unique kebab-case list" % entry_id)

        _relative_path(entry.get("dir"), "dir", entry_id)
        _relative_path(entry.get("route_fixture", "route.json"), "route_fixture", entry_id)
        source = entry.get("source")
        binary = entry.get("binary")
        if not source and not binary:
            raise SuiteValidationError("%s requires source or binary" % entry_id)
        if source:
            _relative_path(source, "source", entry_id)
        if binary:
            _relative_path(binary, "binary", entry_id)
        for runtime_file in entry.get("runtime_files", []) or []:
            _relative_path(runtime_file, "runtime_files", entry_id)

        verify = entry.get("verify")
        if not isinstance(verify, Mapping) or verify.get("kind") not in VERIFY_KINDS:
            raise SuiteValidationError("%s.verify.kind is invalid" % entry_id)
        if not isinstance(entry.get("env", {}), Mapping):
            raise SuiteValidationError("%s.env must be an object" % entry_id)
    return doc
