"""Bounded canonical analysis controls for CTF-Rat Desktop.

Desktop never accepts analysis argv or target paths from HTTP. The challenge's
validated rat.run/v1 manifest selects the target, and this adapter invokes the
existing ``rat`` front door for FAST/DEEP briefing and bounded query cards.
STATE, cache, artifacts, routing, and verification remain owned by the canonical
runtime.
"""
from __future__ import annotations

import json
import os
import re
import threading
from typing import Any

from .run_manifest import read as read_run_manifest, sha256_file
from .runner import ResourceLimits, run as runner_run
from .schema import validate

STATUS_SCHEMA = "rat.desktop.analysis-status/v1"
RUN_SCHEMA = "rat.desktop.analysis-run/v1"
FUNCTION_SCHEMA = "rat.desktop.function-query/v1"
ORACLE_SCHEMA = "rat.desktop.oracle-query/v1"
SLICE_SCHEMA = "rat.desktop.slice-query/v1"
MODES = {"fast", "deep"}
MAX_RESULT_BYTES = 256 * 1024
QUERY_BUDGET_BYTES = 32 * 1024


def _input_for_role(manifest: dict[str, Any], role: str) -> dict[str, Any] | None:
    matches = [item for item in manifest.get("inputs", []) if item.get("role") == role]
    if len(matches) > 1:
        raise ValueError("run manifest contains multiple %s inputs" % role)
    return matches[0] if matches else None


def _safe_local_input(root: str, name: str, expected: dict[str, Any], role: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(name, str) or not name or os.path.basename(name) != name or name in {".", ".."}:
        raise ValueError("run manifest %s input must be a challenge-local basename" % role)
    root_real = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root_real, name))
    if os.path.commonpath([root_real, path]) != root_real:
        raise ValueError("run manifest %s input escapes challenge root" % role)
    if not os.path.isfile(path):
        raise ValueError("run manifest %s input is missing" % role)
    actual_digest = sha256_file(path)
    if actual_digest != expected.get("sha256"):
        raise ValueError("run manifest %s input digest does not match local file" % role)
    actual_size = os.path.getsize(path)
    if actual_size != expected.get("size"):
        raise ValueError("run manifest %s input size does not match local file" % role)
    return path, {"role": role, "name": name, "sha256": actual_digest, "size": actual_size}


def resolve_target(challenge_root: str) -> dict[str, Any]:
    """Resolve the canonical local binary/libc selected by ``run.json``.

    The returned ``_binary_path`` / ``_libc_path`` fields are private adapter
    details and must not be serialized to clients.
    """
    root = os.path.abspath(challenge_root)
    manifest = read_run_manifest(os.path.join(root, "run.json"))
    binary_input = _input_for_role(manifest, "binary")
    if binary_input is None:
        raise ValueError("run manifest has no binary input")
    scaffold = manifest.get("scaffold") if isinstance(manifest.get("scaffold"), dict) else {}
    binary_name = scaffold.get("binary") or binary_input.get("name")
    binary_path, binary = _safe_local_input(root, binary_name, binary_input, "binary")

    libc_path = None
    libc = None
    libc_input = _input_for_role(manifest, "libc")
    if libc_input is not None:
        libc_name = scaffold.get("libc") or libc_input.get("name")
        libc_path, libc = _safe_local_input(root, libc_name, libc_input, "libc")

    return {
        "run_id": manifest.get("run_id"),
        "challenge": (manifest.get("challenge") or {}).get("name"),
        "binary": binary,
        "libc": libc,
        "_binary_path": binary_path,
        "_libc_path": libc_path,
    }


def _public_target(target: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in target.items() if not key.startswith("_")}


def _function_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("function name must be a string")
    name = value.strip()
    if not name or len(name.encode("utf-8")) > 256:
        raise ValueError("function name must be between 1 and 256 UTF-8 bytes")
    if any(not char.isprintable() for char in name):
        raise ValueError("function name must contain printable characters only")
    return name


def _address(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("slice target must be an address string")
    text = value.strip()
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", text):
        raise ValueError("slice target must be a hexadecimal or decimal address")
    parsed = int(text[2:], 16) if text.lower().startswith("0x") else int(text, 10)
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("slice target address is out of range")
    return hex(parsed)


def _query_diagnostic(doc: dict[str, Any], stderr: str) -> str | None:
    diagnostics = doc.get("diagnostics", [])
    if diagnostics and isinstance(diagnostics[0], dict):
        message = diagnostics[0].get("message")
        if isinstance(message, str) and message:
            return message
    return stderr or None


def _query_output(result, target: dict[str, Any], label: str) -> tuple[str, dict[str, Any] | None, str | None]:
    stderr = result.stderr.preview.decode("utf-8", "replace")[-4096:]
    if result.timed_out:
        return "timeout", None, "%s timed out" % label
    if result.stdout.truncated:
        return "error", None, "%s exceeded desktop output budget" % label
    try:
        doc = json.loads(result.stdout.preview.decode("utf-8"))
        validate(doc, "rat.query-result/v1")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return "error", None, stderr or "invalid %s result: %s" % (label, exc)

    expected = target["binary"]["sha256"]
    provenance = doc.get("provenance") if isinstance(doc.get("provenance"), dict) else {}
    reported = provenance.get("binary_sha256")
    if isinstance(reported, str) and reported != expected:
        return "error", None, "%s result does not match the canonical run manifest" % label
    if sha256_file(target["_binary_path"]) != expected:
        return "error", None, "%s target changed during analysis" % label

    status = doc.get("status") if doc.get("status") in {"ok", "partial", "error"} else "error"
    diagnostic = _query_diagnostic(doc, stderr if result.exit_code != 0 else "")
    return status, doc, diagnostic


class AnalysisManager:
    """Serialize bounded Desktop-triggered calls into the canonical ``rat`` CLI."""

    def __init__(self, challenge_root: str):
        self.root = os.path.abspath(challenge_root)
        self._run_lock = threading.Lock()

    def status(self) -> dict[str, Any]:
        try:
            target = resolve_target(self.root)
            return {
                "schema": STATUS_SCHEMA,
                "ready": True,
                "busy": self._run_lock.locked(),
                "target": _public_target(target),
                "modes": {
                    "fast": True,
                    "deep": True,
                    "function": True,
                    "oracle": True,
                    "slice": True,
                    "verify_status": True,
                },
                "reason": None,
            }
        except (OSError, ValueError) as exc:
            return {
                "schema": STATUS_SCHEMA,
                "ready": False,
                "busy": self._run_lock.locked(),
                "target": None,
                "modes": {
                    "fast": False,
                    "deep": False,
                    "function": False,
                    "oracle": False,
                    "slice": False,
                    "verify_status": True,
                },
                "reason": str(exc),
            }

    def brief(self, mode: str) -> dict[str, Any]:
        if mode not in MODES:
            raise ValueError("analysis mode must be fast or deep")
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("another desktop analysis request is already running")
        try:
            target = resolve_target(self.root)
            rat = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rat"))
            argv = [rat, "brief", target["_binary_path"], "--format", "json", "--budget-tokens", "1500"]
            if mode == "fast":
                argv.append("--fast")
            if target.get("_libc_path"):
                argv.extend(["--libc", target["_libc_path"]])
            timeout = 30.0 if mode == "fast" else 90.0
            result = runner_run(
                argv,
                cwd=self.root,
                timeout_seconds=timeout,
                limits=ResourceLimits(cpu_seconds=60),
                preview_bytes=MAX_RESULT_BYTES,
                max_output_bytes=MAX_RESULT_BYTES,
                tool_version="desktop-v0.3",
            )
            stderr = result.stderr.preview.decode("utf-8", "replace")[-4096:]
            base = {
                "schema": RUN_SCHEMA,
                "mode": mode,
                "target": _public_target(target),
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
            }
            if result.timed_out:
                return {**base, "status": "timeout", "result": None, "diagnostic": "rat brief timed out"}
            if result.stdout.truncated:
                return {**base, "status": "error", "result": None, "diagnostic": "rat brief exceeded desktop output budget"}
            if result.exit_code != 0:
                return {**base, "status": "error", "result": None, "diagnostic": stderr or "rat brief failed"}
            try:
                card = json.loads(result.stdout.preview.decode("utf-8"))
                validate(card, "rat.brief-card/v1")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                return {**base, "status": "error", "result": None, "diagnostic": "invalid rat brief result: %s" % exc}
            if card.get("binary_sha256") != target["binary"]["sha256"]:
                return {
                    **base,
                    "status": "error",
                    "result": None,
                    "diagnostic": "rat brief analyzed bytes that do not match the canonical run manifest",
                }
            if target.get("libc") is not None:
                card_libc = card.get("libc") if isinstance(card.get("libc"), dict) else {}
                if card_libc.get("sha256") != target["libc"]["sha256"]:
                    return {
                        **base,
                        "status": "error",
                        "result": None,
                        "diagnostic": "rat brief libc bytes do not match the canonical run manifest",
                    }
            return {**base, "status": "ok", "result": card, "diagnostic": stderr or None}
        finally:
            self._run_lock.release()

    def function(self, name: str) -> dict[str, Any]:
        name = _function_name(name)
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("another desktop analysis request is already running")
        try:
            target = resolve_target(self.root)
            rat = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rat"))
            argv = [
                rat, "query", "func", target["_binary_path"], name,
                "--fast", "--budget-bytes", str(QUERY_BUDGET_BYTES), "--format", "json",
            ]
            result = runner_run(
                argv,
                cwd=self.root,
                timeout_seconds=30.0,
                limits=ResourceLimits(cpu_seconds=30),
                preview_bytes=MAX_RESULT_BYTES,
                max_output_bytes=MAX_RESULT_BYTES,
                tool_version="desktop-v0.3",
            )
            status, doc, diagnostic = _query_output(result, target, "rat query func")
            return {
                "schema": FUNCTION_SCHEMA,
                "name": name,
                "target": _public_target(target),
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
                "status": status,
                "result": doc,
                "diagnostic": diagnostic,
            }
        finally:
            self._run_lock.release()

    def oracle(self) -> dict[str, Any]:
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("another desktop analysis request is already running")
        try:
            target = resolve_target(self.root)
            rat = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rat"))
            argv = [
                rat, "query", "oracle", target["_binary_path"],
                "--fast", "--budget-bytes", str(QUERY_BUDGET_BYTES), "--format", "json",
            ]
            result = runner_run(
                argv,
                cwd=self.root,
                timeout_seconds=30.0,
                limits=ResourceLimits(cpu_seconds=30),
                preview_bytes=MAX_RESULT_BYTES,
                max_output_bytes=MAX_RESULT_BYTES,
                tool_version="desktop-v0.3",
            )
            status, doc, diagnostic = _query_output(result, target, "rat query oracle")
            return {
                "schema": ORACLE_SCHEMA,
                "target": _public_target(target),
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
                "status": status,
                "result": doc,
                "diagnostic": diagnostic,
            }
        finally:
            self._run_lock.release()

    def slice(self, backward: str) -> dict[str, Any]:
        backward = _address(backward)
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("another desktop analysis request is already running")
        try:
            target = resolve_target(self.root)
            rat = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rat"))
            argv = [
                rat, "query", "slice", target["_binary_path"],
                "--backward", backward, "--depth", "2", "--source", "stdin", "--format", "json",
            ]
            result = runner_run(
                argv,
                cwd=self.root,
                timeout_seconds=90.0,
                limits=ResourceLimits(cpu_seconds=60),
                preview_bytes=MAX_RESULT_BYTES,
                max_output_bytes=MAX_RESULT_BYTES,
                tool_version="desktop-v0.3",
            )
            status, doc, diagnostic = _query_output(result, target, "rat query slice")
            return {
                "schema": SLICE_SCHEMA,
                "backward": backward,
                "target": _public_target(target),
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
                "status": status,
                "result": doc,
                "diagnostic": diagnostic,
            }
        finally:
            self._run_lock.release()
