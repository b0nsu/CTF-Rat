import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from ratlib.artifact import put_bytes
from ratlib.contracts import (
    parse_proof_value,
    prepare_proof_invocation,
    record_proof_observation,
)
from ratlib.state_v2 import (
    VERIFIER_CONTRACT_VERSION,
    Stream,
    _file_digest,
    environment_fingerprint,
    revise_primitive,
    trusted_producer_for_build,
)


def direct_gdbq_doc(root, subject, stdout):
    tool = ROOT / "bin" / "gdbq"
    build = _file_digest(str(tool))
    if trusted_producer_for_build(build) != "gdbq":
        raise RuntimeError("test requires registered gdbq build")
    subject_digest = _file_digest(str(subject))
    capture = put_bytes(
        stdout.encode(),
        kind="stdout",
        media_type="text/plain; charset=utf-8",
        logical_name="stdout.txt",
        root=root,
    )
    policy = {
        "level": "direct",
        "promotion_allowed": True,
        "producer": "gdbq",
        "registry": VERIFIER_CONTRACT_VERSION,
        "build_digest": build,
        "subject_digest": subject_digest,
        "environment_digest": environment_fingerprint(),
        "mode": "measure",
    }
    now = "2026-01-01T00:00:00+00:00"
    doc = {
        "schema": "rat.tool-result/v1",
        "tool": {"name": "gdbq", "version": "legacy-adapter/v1", "build_digest": build},
        "run_id": "local",
        "invocation_id": "invoke_test",
        "status": "ok",
        "started_at": now,
        "finished_at": now,
        "duration_ms": 1,
        "inputs": [{"role": "input", "digest": subject_digest, "size": subject.stat().st_size}],
        "parameters": {},
        "summary": {"stdout_bytes": len(stdout), "stderr_bytes": 0, "truncated": False},
        "artifacts": [{key: capture[key] for key in ("kind", "digest", "media_type", "size", "logical_name")}],
        "findings": [],
        "diagnostics": [],
        "exit": {"code": 0, "signal": None, "timed_out": False, "cancelled": False},
        "provenance": {
            "platform": {},
            "dependency_versions": {},
            "policy_digest": "sha256:" + hashlib.sha256(b"proof-test").hexdigest(),
            "cache": {"key": "proof-test", "hit": False, "source_invocation": None},
        },
        "extensions": {"evidence_policy": policy},
        "tool_name": "gdbq",
        "params_digest": "unindexed",
        "cache_state": "miss",
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    envelope = put_bytes(
        raw,
        kind="tool-result",
        media_type="application/json",
        logical_name="result.json",
        root=root,
    )
    doc["extensions"]["envelope_digest"] = envelope["digest"]
    return doc


class ProofInvocationTests(unittest.TestCase):
    def test_pwn_proof_builds_commands_and_rejects_arbitrary_gdb(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            payload = pathlib.Path(directory, "input.bin")
            payload.write_bytes(b"AAAA")
            argv = prepare_proof_invocation(
                "gdbq",
                str(ROOT / "bin" / "gdbq"),
                [],
                direct_subject=str(subject),
                proof="pwn-memory-control",
                proof_input=str(payload),
                proof_break="stop_here",
                proof_address="$rsp+8",
                proof_marker="41414141",
            )
            self.assertEqual(argv[1], str(subject))
            self.assertEqual(argv[2], "break stop_here")
            self.assertIn("run < ", argv[3])
            self.assertEqual(argv[4], "x/4bx $rsp+8")
            with self.assertRaisesRegex(ValueError, "do not accept arbitrary"):
                prepare_proof_invocation(
                    "gdbq",
                    str(ROOT / "bin" / "gdbq"),
                    ["run", "info registers"],
                    direct_subject=str(subject),
                    proof="pwn-control-state",
                    proof_input=str(payload),
                    proof_break="stop_here",
                )

    def test_unsafe_gdb_expression_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            payload = pathlib.Path(directory, "input.bin")
            payload.write_bytes(b"AAAA")
            with self.assertRaisesRegex(ValueError, "safe --proof-address"):
                prepare_proof_invocation(
                    "gdbq",
                    str(ROOT / "bin" / "gdbq"),
                    [],
                    direct_subject=str(subject),
                    proof="pwn-memory-control",
                    proof_input=str(payload),
                    proof_break="stop_here",
                    proof_address="$rsp; shell id",
                    proof_marker="4141",
                )


class ProofParserTests(unittest.TestCase):
    def test_pwn_semantic_parsers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            state = (
                "Breakpoint 1, stop_here ()\n"
                "rip            0x401234  0x401234 <stop_here>\n"
                "rsp            0x7fffffffe000  0x7fffffffe000\n"
                "rbp            0x7fffffffe020  0x7fffffffe020\n"
            )
            state_doc = direct_gdbq_doc(str(root), subject, state)
            value = parse_proof_value("pwn-control-state", state_doc, str(root))
            self.assertEqual(value["rip"], 0x401234)
            self.assertEqual(value["rsp"], 0x7FFFFFFFE000)

            memory = "Breakpoint 1, stop_here ()\n0x7fffffffe008:\t0x41\t0x42\t0x43\t0x44\n"
            memory_doc = direct_gdbq_doc(str(root), subject, memory)
            value = parse_proof_value(
                "pwn-memory-control",
                memory_doc,
                str(root),
                proof_address="$rsp+8",
                proof_marker="41424344",
            )
            self.assertEqual(value["marker_hex"], "41424344")

            target = "Breakpoint 1, stop_here ()\n0x7fffffffe008:\t0x0000000000401234\n"
            target_doc = direct_gdbq_doc(str(root), subject, target)
            value = parse_proof_value(
                "pwn-control-target",
                target_doc,
                str(root),
                proof_address="$rsp+8",
                proof_target="0x401234",
            )
            self.assertEqual(value["target"], 0x401234)

    def test_rev_semantic_parsers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            solution = "  stdin  = b'ABCD'\n           hex: 41424344\n"
            solution_doc = direct_gdbq_doc(str(root), subject, solution)
            value = parse_proof_value("rev-solution-input", solution_doc, str(root))
            self.assertEqual(value["solutions"], {"stdin": "41424344"})

            oracle = "Correct!\n[Inferior 1 (process 123) exited normally]\n"
            oracle_doc = direct_gdbq_doc(str(root), subject, oracle)
            self.assertEqual(
                parse_proof_value(
                    "rev-success-oracle",
                    oracle_doc,
                    str(root),
                    proof_expect="Correct!",
                )["exit"],
                "normal",
            )

            replay = oracle + "RAT_REPLAY_COMPLETE\n"
            replay_doc = direct_gdbq_doc(str(root), subject, replay)
            self.assertEqual(
                parse_proof_value(
                    "rev-concrete-replay",
                    replay_doc,
                    str(root),
                    proof_expect="Correct!",
                )["expected"],
                "Correct!",
            )

    def test_marker_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            doc = direct_gdbq_doc(
                str(root),
                subject,
                "Breakpoint 1, stop_here ()\n0x1000:\t0x41\t0x42\n",
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                parse_proof_value(
                    "pwn-memory-control",
                    doc,
                    str(root),
                    proof_address="$rsp",
                    proof_marker="4344",
                )


@unittest.skipUnless(shutil.which("gdb") and shutil.which("cc"), "gdb+cc required")
@unittest.skipUnless(platform.machine() in {"x86_64", "amd64"}, "x86-64 proof fixture")
class ProofProducerIntegrationTests(unittest.TestCase):
    def test_three_generated_gdbq_proofs_reach_control_flow_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            source = directory / "proof.c"
            binary = directory / "proof"
            payload = directory / "payload.bin"
            payload.write_bytes(b"ABCD")
            source.write_text(
                "#include <unistd.h>\n"
                "__attribute__((noinline)) void proof_stop(unsigned char *buf, unsigned long *target) {\n"
                "  __asm__ volatile(\"\" ::: \"memory\");\n"
                "}\n"
                "int main(void) {\n"
                "  unsigned char buf[8] = {0};\n"
                "  unsigned long target = 0x401234UL;\n"
                "  if (read(0, buf, 4) != 4) return 2;\n"
                "  proof_stop(buf, &target);\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            built = subprocess.run(
                ["cc", "-g", "-O0", "-fno-pie", "-no-pie", "-o", str(binary), str(source)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)

            def proof(mode, *extra):
                command = [
                    str(ROOT / "bin" / "rat-adapt"),
                    "--root", str(directory / ".rat"),
                    "--input", str(binary),
                    "--direct-subject", str(binary),
                    "--proof", mode,
                    "--proof-input", str(payload),
                    "--proof-break", "proof_stop",
                    *extra,
                    "gdbq",
                ]
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                return json.loads(result.stdout)["extensions"]["proof_observation"]["observation_id"]

            reg = proof("pwn-control-state")
            marker_obs = proof(
                "pwn-memory-control",
                "--proof-address", "$rdi",
                "--proof-marker", "41424344",
            )
            target_obs = proof(
                "pwn-control-target",
                "--proof-address", "$rsi",
                "--proof-target", "0x401234",
            )

            stream = Stream(str(directory))
            primitive = {
                "primitive_id": "control",
                "class": "control-flow",
                "status": "candidate",
                "self_evidence": [],
                "input_digest": _file_digest(str(binary)),
                "environment_digest": environment_fingerprint(),
            }
            revise_primitive(stream, primitive)
            revise_primitive(
                stream,
                {
                    **primitive,
                    "status": "pass",
                    "self_evidence": [reg, marker_obs, target_obs],
                },
            )
            passed = stream.view()["primitives"]["control"]
            self.assertEqual(passed["status"], "pass")
            self.assertEqual(passed["extensions"]["proof_contract"], "control-flow/v1")

class ProofStateWriterTests(unittest.TestCase):
    def test_records_direct_canonical_observation_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            doc = direct_gdbq_doc(
                str(root),
                subject,
                "Breakpoint 1, stop_here ()\n"
                "rip 0x401234\n"
                "rsp 0x7fffffffe000\n"
                "rbp 0x7fffffffe020\n",
            )
            first = record_proof_observation(
                doc,
                root=str(root),
                direct_subject=str(subject),
                proof="pwn-control-state",
            )
            second = record_proof_observation(
                doc,
                root=str(root),
                direct_subject=str(subject),
                proof="pwn-control-state",
            )
            self.assertFalse(first["deduplicated"])
            self.assertTrue(second["deduplicated"])
            self.assertEqual(first["observation_id"], second["observation_id"])
            stored = Stream(directory).view()["observations"][first["observation_id"]]
            self.assertEqual(stored["kind"], "pwn.reg")
            self.assertEqual(stored["quality"]["level"], "direct")


if __name__ == "__main__":
    unittest.main()
