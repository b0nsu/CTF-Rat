#!/usr/bin/env python3
"""Deterministic orchestration checks through the primitive handoff boundary."""
import argparse, os, subprocess, sys, tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.artifact import put_bytes
from ratlib.orchestration import (
    DEFAULT_BUDGET,
    GateError,
    converge,
    enter,
    finish_phase,
    finish_task,
    invalidate,
    plan_fanout,
    start_task,
)
from ratlib.state_v2 import Stream, revise_primitive

D = "sha256:" + "a" * 64


def observation(stream, observation_id):
    record = put_bytes(observation_id.encode(), kind="test-evidence", media_type="text/plain", logical_name=observation_id, root=stream.root, provenance={"evidence_policy": {"level": "direct", "promotion_allowed": True}})
    return {"observation_id": observation_id, "quality": {"level": "direct"}, "validity": {"state": "active"}, "evidence": [record["digest"]]}


def contract(role, phase):
    return {
        "schema": "rat.role-contract/v1",
        "role": role,
        "phase": phase,
        "objective": "probe",
        "allowed_inputs": [],
        "required_outputs": [],
        "forbidden_actions": [],
        "state_write_scope": [],
        "capabilities": {"network_write": False, "repository_write": False, "evidence_promote": False},
        "budgets": dict(DEFAULT_BUDGET),
        "stop_conditions": ["budget"],
    }


def output(task):
    return {"schema": "rat.task-output/v1", "task_id": task["task_id"], "status": "completed", "outputs": {}, "evidence_ids": ["obs"]}


def advance(root, phase):
    enter(root, phase)
    finish_phase(root, phase)


def to_p2(root):
    advance(root, "solve-P0")
    advance(root, "solve-P1")
    stream = Stream(root)
    for observation_id in ("o1", "o2", "obs"):
        stream.append("observation.recorded", observation(stream, observation_id))
    return enter(root, "solve-P2")


def to_p3_with_pass(root):
    for phase in ("solve-P0", "solve-P1", "solve-P2"):
        advance(root, phase)
    stream = Stream(root)
    for observation_id in ("o1", "o2", "o3"):
        stream.append("observation.recorded", observation(stream, observation_id))
    primitive = {"primitive_id": "p", "input_digest": D, "environment_digest": D}
    revise_primitive(stream, {**primitive, "status": "candidate", "self_evidence": []})
    revise_primitive(stream, {**primitive, "status": "pass", "self_evidence": ["o1", "o2", "o3"]})
    enter(root, "solve-P3")


parser = argparse.ArgumentParser()
parser.add_argument(
    "--scenario",
    choices=["converge", "invalidate-cancel", "handoff", "p4-blocked"],
    required=True,
)
args = parser.parse_args()

with tempfile.TemporaryDirectory() as root:
    if args.scenario == "converge":
        checkpoint = to_p2(root)
        branches = [
            {"hypothesis_id": "h1", "objective": "one", "falsification": "no-one", "evidence_ids": ["o1"]},
            {"hypothesis_id": "h2", "objective": "two", "falsification": "no-two", "evidence_ids": ["o2"]},
        ]
        plan_fanout(
            root,
            branches,
            {"uncertainty_set": ["h1", "h2"], "evidence_ids": ["o1", "o2"]},
            {"remaining": 80, "per_branch": 20, "converge": 20},
        )
        tasks = [
            start_task(
                root,
                contract("hypothesis", "solve-P2"),
                checkpoint_id=checkpoint["checkpoint_id"],
                inputs=[value],
                dependencies=["o%d" % (index + 1)],
            )
            for index, value in enumerate(("one", "two"))
        ]
        for task in tasks:
            finish_task(root, task["task_id"], "completed", output(task))
        assert converge(root, ["h1"], ["h2"], [], [{"evidence_ids": ["o1"]}])["retained"] == ["h1"]
    elif args.scenario == "invalidate-cancel":
        checkpoint = to_p2(root)
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        task = start_task(
            root,
            contract("hypothesis", "solve-P2"),
            checkpoint_id=checkpoint["checkpoint_id"],
            inputs=["one"],
            dependencies=["o1"],
            child_pid=child.pid,
        )
        assert invalidate(root, ["o1"], "refuted")["cancelled"] == [task["task_id"]]
        child.wait(timeout=3)
        assert child.poll() is not None
    elif args.scenario == "handoff":
        to_p3_with_pass(root)
        finish_phase(root, "solve-P3", terminal=True)
        assert any(event["type"] == "operator.handoff.required" for event in Stream(root).read())
    elif args.scenario == "p4-blocked":
        to_p3_with_pass(root)
        finish_phase(root, "solve-P3")
        try:
            enter(root, "solve-P4")
        except GateError:
            pass
        else:
            raise AssertionError("post-primitive exploit phase was allowed")

print("orchestration %s: PASS" % args.scenario)
