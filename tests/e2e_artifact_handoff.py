#!/usr/bin/env python3
"""Role B verifies a finding from checkpoint/artifacts, never Role A stdout."""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import get
from ratlib.contracts import execute
from ratlib.state_v2 import Stream, revise_finding

with tempfile.TemporaryDirectory() as work:
    stream = Stream(work)
    # Role A invokes a real legacy analysis tool through the P1 adapter.  Its
    # stdout is unavailable to Role B except through the artifact digest.
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    result = execute([os.path.join(root, "bin", "revq"), "selftest"], root=stream.root)
    stdout = next(a for a in result["artifacts"] if a["kind"] == "stdout")
    observation = {"observation_id":"obs_marker", "quality":{"level":"direct"},
                   "validity":{"state":"active"}, "evidence":[stdout["digest"]]}
    stream.append("observation.recorded", observation, actor="role-a")
    revise_finding(stream, {"finding_id":"finding_marker", "state":"proposed", "evidence_observation_ids":[]})
    revise_finding(stream, {"finding_id":"finding_marker", "state":"supported",
                            "evidence_observation_ids":["obs_marker"]})
    checkpoint = stream.checkpoint(phase="solve-P1", task_id="role-a", role="scout", reason="handoff")
    # Role B receives the checkpoint object and store only.
    context = json.loads(get(checkpoint["context_artifact"], root=stream.root))
    assert "finding_marker" in context["active"]["findings"]
    view = stream.view()
    evidence_digest = view["observations"]["obs_marker"]["evidence"][0]
    assert b"ALL GREEN" in get(evidence_digest, root=stream.root)
print("artifact-only handoff: PASS")
