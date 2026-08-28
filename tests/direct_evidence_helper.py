import hashlib
import json
import os
import uuid

from ratlib.artifact import put_bytes
from ratlib.state_v2 import (
    VERIFIER_CONTRACT_VERSION,
    _file_digest,
    environment_fingerprint,
    trusted_producer_for_build,
)


D = "sha256:" + hashlib.sha256(b"p1-local-test").hexdigest()
# A fixed subject/environment for tests that PASS a primitive: the runtime now binds
# every SELF observation's direct evidence to the primitive's input_digest and
# environment_digest, so the three measurements must agree on the binary and host.
# Tests set the primitive's input_digest to CANONICAL_SUBJECT and environment_digest
# to CANONICAL_ENVIRONMENT. The environment digest is tooling-owned (not chosen), so
# it mirrors exactly what the production issuance path stamps.
CANONICAL_SUBJECT = "sha256:" + hashlib.sha256(b"ctf-rat-canonical-subject").hexdigest()
CANONICAL_ENVIRONMENT = environment_fingerprint()
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_PATHS = {
    "gdbq": os.path.join(_REPO, "bin", "gdbq"),
    "symsolve": os.path.join(_REPO, "bin", "symsolve"),
    "symsolve.py": os.path.join(_REPO, "solve", "_template", "rev", "symsolve.py"),
}


def direct_evidence_envelope(*, root, producer, measurement, summary=None, subject_digest=None):
    """Test helper: mint a v2 direct envelope bound to a measured subject.

    Mirrors the production issuance path (``contracts.execute`` with
    ``direct_subject``): trust rests on the verifier's content identity
    (build_digest, path-independent) plus a ``subject_digest`` recorded in the
    envelope's ``inputs`` and a tooling-owned ``environment_digest``. The policy
    carries NO absolute executable path. ``subject_digest`` defaults to
    CANONICAL_SUBJECT so three independent measurements share one subject (as three
    SELF measurements of the same primitive must); pass it to model a different one.
    """
    if "/" in producer or producer in ("", ".", ".."):
        raise ValueError("producer must be a basename")
    if not measurement:
        raise ValueError("measurement is required")
    root = os.path.abspath(root)
    tool = _PATHS[producer]
    build_digest = _file_digest(tool)
    if trusted_producer_for_build(build_digest) != producer:
        raise RuntimeError("canonical direct verifier is not registered: %s" % producer)
    measurement_rec = put_bytes(
        measurement, kind="measurement", media_type="application/octet-stream",
        logical_name="measurement-%s.bin" % uuid.uuid4().hex, root=root,
    )
    subject_digest = subject_digest or CANONICAL_SUBJECT
    policy = {
        "level": "direct", "promotion_allowed": True, "producer": producer,
        "registry": VERIFIER_CONTRACT_VERSION, "build_digest": build_digest,
        "subject_digest": subject_digest, "environment_digest": CANONICAL_ENVIRONMENT,
        "mode": "--find-str",
    }
    now = "2026-01-01T00:00:00+00:00"
    doc = {
        "schema": "rat.tool-result/v1",
        "tool": {"name": producer, "version": "test-helper/canonical-policy", "build_digest": build_digest},
        "run_id": "local", "invocation_id": "invoke_" + uuid.uuid4().hex,
        "status": "ok", "started_at": now, "finished_at": now, "duration_ms": 0,
        "inputs": [{"role": "input", "digest": subject_digest, "size": len(measurement)}],
        "parameters": {"summary": summary or ""},
        "summary": {"truncated": False},
        "artifacts": [{k: measurement_rec[k] for k in ("kind", "digest", "media_type", "size", "logical_name")}],
        "findings": [], "diagnostics": [],
        "exit": {"code": 0, "signal": None, "timed_out": False, "cancelled": False},
        "provenance": {"platform": {}, "dependency_versions": {}, "policy_digest": D, "cache": {}},
        "extensions": {"evidence_policy": policy},
    }
    return put_bytes(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(),
        kind="tool-result", media_type="application/json", logical_name="result.json", root=root,
    )["digest"]
