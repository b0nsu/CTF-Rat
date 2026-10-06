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


def direct_gdbq_doc(root, subject, stdout, *, inferior=None, producer="gdbq"):
    """Synthetic immutable capture for unit tests; not an execution attestation."""
    tool = ROOT / "bin" / producer
    build = _file_digest(str(tool))
    if trusted_producer_for_build(build) != producer:
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
        "producer": producer,
        "registry": VERIFIER_CONTRACT_VERSION,
        "build_digest": build,
        "subject_digest": subject_digest,
        "environment_digest": environment_fingerprint(),
        "mode": "measure",
    }
    now = "2026-01-01T00:00:00+00:00"
    doc = {
        "schema": "rat.tool-result/v1",
        "tool": {"name": producer, "version": "legacy-adapter/v1", "build_digest": build},
        "run_id": "local",
        "invocation_id": "invoke_test",
        "status": "ok",
        "started_at": now,
        "finished_at": now,
        "duration_ms": 1,
        "inputs": [{"role": "input", "digest": subject_digest, "size": subject.stat().st_size}],
        "parameters": {"proof": {"expect": "Correct!"}},
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
        "tool_name": producer,
        "params_digest": "unindexed",
        "cache_state": "miss",
    }
    if producer == "gdbq":
        debugger = put_bytes(stdout.encode(), kind="debugger-output", media_type="text/plain",
                             logical_name="debugger.txt", root=root)
        doc["artifacts"].append({key: debugger[key] for key in
                                 ("kind", "digest", "media_type", "size", "logical_name")})
        doc["extensions"]["debugger_capture"] = {
            "digest": debugger["digest"], "invocation_id": doc["invocation_id"],
            "subject_digest": subject_digest, "complete": True, "truncated": False,
        }
    if inferior is not None:
        out = put_bytes(inferior.encode(), kind="inferior-output", media_type="text/plain",
                        logical_name="inferior.txt", root=root)
        doc["artifacts"].append({key: out[key] for key in ("kind", "digest", "media_type", "size", "logical_name")})
        doc["extensions"]["inferior_capture"] = {"digest": out["digest"], "invocation_id": doc["invocation_id"],
                "subject_digest": subject_digest, "complete": True, "truncated": False}
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
            self.assertEqual(argv[-2], "x/4bx $rsp+8")
            self.assertIn("RAT_PROOF_ADDRESS=", argv[-3])
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
                "RAT_PROOF_MEASURE_BEGIN\n"
                "rip            0x401234  0x401234 <stop_here>\n"
                "rsp            0x7fffffffe000  0x7fffffffe000\n"
                "rbp            0x7fffffffe020  0x7fffffffe020\n"
                "RAT_PROOF_MEASURE_END\n"
            )
            state_doc = direct_gdbq_doc(str(root), subject, state)
            value = parse_proof_value("pwn-control-state", state_doc, str(root))
            self.assertEqual(value["rip"], 0x401234)
            self.assertEqual(value["rsp"], 0x7FFFFFFFE000)

            memory = ("Breakpoint 1, stop_here ()\nRAT_PROOF_MEASURE_BEGIN\n"
                      "RAT_PROOF_ADDRESS=0x7fffffffe008\n"
                      "0x7fffffffe008:\t0x41\t0x42\t0x43\t0x44\n"
                      "RAT_PROOF_MEASURE_END\n")
            memory_doc = direct_gdbq_doc(str(root), subject, memory)
            value = parse_proof_value(
                "pwn-memory-control",
                memory_doc,
                str(root),
                proof_address="$rsp+8",
                proof_marker="41424344",
            )
            self.assertEqual(value["marker_hex"], "41424344")

            target = ("Breakpoint 1, stop_here ()\nRAT_PROOF_MEASURE_BEGIN\n"
                      "RAT_PROOF_ADDRESS=0x7fffffffe008\n"
                      "0x7fffffffe008:\t0x0000000000401234\n"
                      "RAT_PROOF_MEASURE_END\n")
            target_doc = direct_gdbq_doc(str(root), subject, target)
            value = parse_proof_value(
                "pwn-control-target",
                target_doc,
                str(root),
                proof_address="$rsp+8",
                proof_target="0x401234",
            )
            self.assertEqual(value["word"], 0x401234)

    def test_rev_semantic_parsers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            solution = "  stdin  = b'ABCD'\n           hex: 41424344\n"
            solution_doc = direct_gdbq_doc(str(root), subject, solution, producer="symsolve")
            value = parse_proof_value("rev-solution-input", solution_doc, str(root))
            self.assertEqual(value["solutions"], {"stdin": "41424344"})

            for output, expected in (
                ("  file   = b'FLAG'\n         hex: 464c4147\n", {"file": "464c4147"}),
                ("  stdin = b'A'\n         hex: 41\n"
                 "  file = b'B'\n         hex: 42\n", {"stdin": "41", "file": "42"}),
                ("  argv1 = b'A'\n         hex: 41\n"
                 "  file = b'B'\n         hex: 42\n", {"argv1": "41", "file": "42"}),
            ):
                with self.subTest(output=output):
                    doc = direct_gdbq_doc(str(root), subject, output, producer="symsolve")
                    self.assertEqual(
                        parse_proof_value("rev-solution-input", doc, str(root))["solutions"],
                        expected,
                    )

            oracle = "Correct!\n[Inferior 1 (process 123) exited normally]\n"
            oracle_doc = direct_gdbq_doc(str(root), subject, oracle, inferior="Correct!\n")
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
            replay_doc = direct_gdbq_doc(str(root), subject, replay, inferior="Correct!\n")
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
                "Breakpoint 1, stop_here ()\nRAT_PROOF_MEASURE_BEGIN\n"
                "RAT_PROOF_ADDRESS=0x1000\n0x1000:\t0x41\t0x42\n"
                "RAT_PROOF_MEASURE_END\n",
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                parse_proof_value(
                    "pwn-memory-control",
                    doc,
                    str(root),
                    proof_address="$rsp",
                    proof_marker="4344",
                )

    def test_pwn_parser_uses_bound_debugger_response_and_checks_address(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            debugger = ("program log: 0x401234 0x41 0x42\n"
                        "Breakpoint 1, stop_here ()\nRAT_PROOF_MEASURE_BEGIN\n"
                        "RAT_PROOF_ADDRESS=0x1000\n0x1008:\t0x41\t0x42\n"
                        "RAT_PROOF_MEASURE_END\n")
            doc = direct_gdbq_doc(str(root), subject, debugger, inferior="0x1000: 0x41 0x42\n")
            with self.assertRaisesRegex(ValueError, "address does not match"):
                parse_proof_value("pwn-memory-control", doc, str(root),
                                  proof_address="$rsp", proof_marker="4142")

            good = debugger.replace("0x1008:\t", "0x1000:\t")
            doc = direct_gdbq_doc(str(root), subject, good, inferior="0x2000: 0x99 0x99\n")
            self.assertEqual(
                parse_proof_value("pwn-memory-control", doc, str(root),
                                  proof_address="$rsp", proof_marker="4142")["marker_hex"],
                "4142",
            )


@unittest.skipUnless(shutil.which("gdb") and shutil.which("cc"), "gdb+cc required")
@unittest.skipUnless(sys.platform == "linux" and platform.machine() in {"x86_64", "amd64"}, "Linux x86-64 proof fixture")
class ProofProducerIntegrationTests(unittest.TestCase):
    def test_general_captures_cannot_reach_control_flow_pass(self):
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
            self.assertEqual(stream.view()["observations"][target_obs]["kind"], "pwn.memory-word")
            with self.assertRaisesRegex(ValueError, "missing proof slots: control-target"):
                revise_primitive(stream, {**primitive, "status": "pass",
                                         "self_evidence": [reg, marker_obs, target_obs]})

class ProofStateWriterTests(unittest.TestCase):
    def test_records_direct_canonical_observation_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory, ".rat")
            subject = pathlib.Path(directory, "chal")
            subject.write_bytes(b"ELF")
            doc = direct_gdbq_doc(
                str(root),
                subject,
                "Breakpoint 1, stop_here ()\nRAT_PROOF_MEASURE_BEGIN\n"
                "rip 0x401234\n"
                "rsp 0x7fffffffe000\n"
                "rbp 0x7fffffffe020\nRAT_PROOF_MEASURE_END\n",
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


class ProofCaptureFixture:
    def build_checker(self, directory, *, success=False):
        source = directory / "checker.c"
        binary = directory / "checker"
        source.write_text('#include <stdio.h>\nint main(void) { puts("' +
                          ('Correct!' if success else 'Wrong!') + '"); return 0; }\n')
        result = subprocess.run(["cc", "-g", "-O0", "-fno-pie", "-no-pie", "-o", str(binary), str(source)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return binary

@unittest.skipUnless(sys.platform == "linux" and shutil.which("gdb") and shutil.which("cc"),
                     "Linux GNU GDB+cc required")
class ProofRevCaptureEngineTests(ProofCaptureFixture, unittest.TestCase):
    def test_actual_inferior_output_success_and_debugger_only_failure(self):
        from ratlib.contracts import execute
        for success in (False, True):
            with self.subTest(success=success), tempfile.TemporaryDirectory(prefix="Correct!") as tmp:
                directory = pathlib.Path(tmp)
                binary = self.build_checker(directory, success=success)
                payload = directory / "input"; payload.write_bytes(b"")
                root = str(directory / ".rat")
                for mode in ("rev-success-oracle", "rev-concrete-replay"):
                    argv = prepare_proof_invocation("gdbq", str(ROOT / "bin" / "gdbq"), [],
                         direct_subject=str(binary), proof=mode, proof_input=str(payload), proof_expect="Correct!")
                    doc = execute(argv, root=root, input_paths=[str(binary), str(payload)],
                         direct_subject=str(binary), parameters={"proof": {"mode": mode, "expect": "Correct!"}})
                    if success:
                        value = parse_proof_value(mode, doc, root, proof_expect="Correct!")
                        self.assertEqual(value["exit"], "normal")
                    else:
                        with self.assertRaisesRegex(ValueError, "does not contain"):
                            parse_proof_value(mode, doc, root, proof_expect="Correct!")

@unittest.skipUnless(sys.platform == "linux" and platform.machine() in {"x86_64", "amd64"}
                     and shutil.which("gdb") and shutil.which("cc"), "Linux x86-64 gdb+cc required")
class ProofCaptureEngineTests(ProofCaptureFixture, unittest.TestCase):
    def test_stripped_instruction_address_and_symbol_breakpoints(self):
        from ratlib.contracts import execute
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            binary = self.build_checker(directory)
            payload = directory / "input"; payload.write_bytes(b"")
            symbols = subprocess.check_output(["nm", str(binary)], text=True)
            address = next(line.split()[0] for line in symbols.splitlines() if line.split()[-1] == "main")
            for location in ("main", "0x" + address):
                if location.startswith("0x"):
                    subprocess.run(["strip", str(binary)], check=True)
                argv = prepare_proof_invocation("gdbq", str(ROOT / "bin" / "gdbq"), [],
                    direct_subject=str(binary), proof="pwn-control-state", proof_input=str(payload), proof_break=location)
                root = str(directory / ".rat")
                doc = execute(
                    argv, root=root, input_paths=[str(binary), str(payload)],
                    direct_subject=str(binary), fresh=True,
                    parameters={"proof": {"mode": "pwn-control-state"}},
                )
                self.assertIn("rip", parse_proof_value("pwn-control-state", doc, root))

    def test_fresh_invocation_bypasses_cache_after_invalidation(self):
        from ratlib.contracts import execute
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp); binary = self.build_checker(directory)
            payload = directory / "input"; payload.write_bytes(b"")
            root = str(directory / ".rat")
            argv = prepare_proof_invocation("gdbq", str(ROOT / "bin" / "gdbq"), [],
                direct_subject=str(binary), proof="pwn-control-state", proof_input=str(payload), proof_break="main")
            def run(fresh=False):
                return execute(
                    argv, root=root, input_paths=[str(binary), str(payload)],
                    direct_subject=str(binary), fresh=fresh,
                    parameters={"proof": {"mode": "pwn-control-state"}},
                )
            first = run()
            recorded = record_proof_observation(first, root=root, direct_subject=str(binary), proof="pwn-control-state")
            Stream(tmp).append("evidence.invalidated", {"observation_ids": [recorded["observation_id"]], "reason": "stale"})
            cached = run(); self.assertTrue(cached["provenance"]["cache"]["hit"])
            with self.assertRaisesRegex(ValueError, "remeasure"):
                record_proof_observation(cached, root=root, direct_subject=str(binary), proof="pwn-control-state")
            fresh = run(True)
            self.assertNotEqual(fresh["extensions"]["envelope_digest"], first["extensions"]["envelope_digest"])
            new = record_proof_observation(fresh, root=root, direct_subject=str(binary), proof="pwn-control-state")
            self.assertNotEqual(new["observation_id"], recorded["observation_id"])


if __name__ == "__main__":
    unittest.main()
