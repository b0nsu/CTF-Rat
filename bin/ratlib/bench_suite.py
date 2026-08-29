"""Small fail-closed validator for ratbench suite manifests.

This is intentionally not a new schema subsystem. ``bench/suite.json`` is the
canonical manifest shape and this module validates only the fields ratbench
needs to compare synthetic, integration, real, and private/held-out corpora
safely.  The optional CLI is a thin preflight/projection adapter for the
existing ``ratbench --suite`` interface; it does not execute benchmarks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
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


def suite_digest(doc):
    """Content digest for the exact validated suite/projection being measured."""
    validate_suite(doc)
    raw = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_suite(path):
    """Load one suite document and validate it before any projection or run."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except json.JSONDecodeError as exc:
        raise SuiteValidationError("invalid suite JSON: %s" % exc) from exc
    except OSError as exc:
        raise SuiteValidationError("cannot read suite: %s" % exc) from exc
    return validate_suite(doc)


def project_suite(doc, *, corpus=None):
    """Return a validated suite projection without mutating the source document.

    A corpus projection fails closed when it would be empty.  This prevents a
    typo or missing local held-out manifest entry from silently producing a
    zero-entry benchmark that could later be mistaken for measurement evidence.
    """
    validate_suite(doc)
    if corpus is None:
        entries = list(doc["entries"])
    else:
        if corpus not in CORPORA:
            raise SuiteValidationError("unknown corpus: %s" % corpus)
        entries = [entry for entry in doc["entries"] if entry.get("corpus") == corpus]
        if not entries:
            raise SuiteValidationError("no entries for corpus: %s" % corpus)
    projected = dict(doc)
    projected["entries"] = entries
    return projected


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python3 -m ratlib.bench_suite",
        description="validate/project a ratbench suite without executing it",
    )
    parser.add_argument("suite", help="suite JSON path")
    parser.add_argument("--corpus", choices=sorted(CORPORA), help="emit only this corpus")
    args = parser.parse_args(argv)
    try:
        projected = project_suite(load_suite(args.suite), corpus=args.corpus)
    except SuiteValidationError as exc:
        print("[bench-suite:err] %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(projected, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
