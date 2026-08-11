"""Shared trust contract for generated CTF-RAT handoff documents."""

import re
from datetime import datetime

from .artifact import get


REQUIRED_SECTIONS = (
    "상태와 범위",
    "Artifact와 환경",
    "핵심 요약",
    "풀이과정",
    "Gate Status",
    "재현",
    "배제된 경로",
    "제약과 운영자 인계",
    "재사용 가능한 지식",
    "AI·자동화 사용",
)
VALID_STATUSES = {"ANALYZING", "PRIMITIVE_PASS", "BLOCKED", "OPERATOR_COMPLETED"}
DOCUMENT_FILES = {
    "handoff": "HANDOFF.md",
    "writeup": "WRITEUP.md",
    "submission": "SUBMISSION.md",
}
ATTESTATION_SCHEMA = "rat.writeup-attestation/v1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def is_digest(value):
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def validate_attestation(document, available_evidence):
    required = {"schema", "operator", "confirmed_at", "result", "evidence"}
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("attestation must contain exactly: %s" % ", ".join(sorted(required)))
    if document["schema"] != ATTESTATION_SCHEMA:
        raise ValueError("unsupported attestation schema")
    for field in ("operator", "confirmed_at", "result"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise ValueError("attestation %s must be a non-empty string" % field)
    try:
        parsed = datetime.fromisoformat(document["confirmed_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("attestation confirmed_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("attestation confirmed_at must include a timezone")
    evidence = document["evidence"]
    if not isinstance(evidence, list) or not evidence or not all(is_digest(item) for item in evidence):
        raise ValueError("attestation evidence must contain SHA-256 digests")
    missing = sorted(set(evidence) - set(available_evidence))
    if missing:
        raise ValueError("attestation references unavailable evidence: %s" % ", ".join(missing))
    return document


def primitive_publication_gaps(primitive, observations, artifact_root=None):
    gaps = []
    for field in ("input_digest", "environment_digest"):
        if not is_digest(primitive.get(field)):
            gaps.append(field)
    evidence_ids = primitive.get("self_evidence", [])
    if not isinstance(evidence_ids, list) or len(evidence_ids) < 3 or len(set(evidence_ids)) < 3:
        gaps.append("self_evidence")
    else:
        for observation_id in evidence_ids:
            observation = observations.get(observation_id, {})
            if observation.get("quality", {}).get("level") != "direct":
                gaps.append("direct_self_evidence")
                break
            if observation.get("validity", {}).get("state") != "active":
                gaps.append("active_self_evidence")
                break
            if not observation.get("evidence") or not all(is_digest(item) for item in observation["evidence"]):
                gaps.append("evidence_artifacts")
                break
            if artifact_root is not None:
                try:
                    for digest in observation["evidence"]:
                        get(digest, root=artifact_root)
                except (OSError, RuntimeError, ValueError):
                    gaps.append("available_evidence_artifacts")
                    break
    extensions = primitive.get("extensions", {})
    if not isinstance(extensions, dict) or not isinstance(extensions.get("reproduction_command"), str) or not extensions.get("reproduction_command", "").strip():
        gaps.append("reproduction_command")
    if not isinstance(extensions, dict) or not isinstance(extensions.get("marker_evidence"), str) or not extensions.get("marker_evidence", "").strip():
        gaps.append("marker_evidence")
    return gaps
