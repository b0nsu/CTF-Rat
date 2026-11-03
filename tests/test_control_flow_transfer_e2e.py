"""A real local GDB producer must satisfy the canonical control-flow gate."""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.state_v2 import Stream, environment_fingerprint, revise_primitive, _file_digest

SOURCE = r'''
#include <unistd.h>
char payload[16];
__attribute__((noinline)) void one(void) { asm volatile("nop"); }
__attribute__((noinline)) void two(void) { asm volatile("nop"); }
__attribute__((noinline)) void transfer(void (*f)(void)) {
    asm volatile("mov %0, %%rax; call *%%rax" : : "r"(f) : "rax", "memory");
}
int main(void) {
    if (read(0, payload, 9) != 9) return 2;
    transfer(payload[0] == 'A' ? one : two);
    return 0;
}
'''


# Reads the input (so the two invocations carry distinct input digests) but
# selects the transfer target from an external counter file that advances on
# every run, independent of the input bytes.  The input never controls the
# target; the A/B differential is spurious.  The deterministic-target check
# (run C repeating input A) must reject this as a false control-flow PASS.
COUNTER_SOURCE = r'''
#include <unistd.h>
#include <stdio.h>
char payload[16];
__attribute__((noinline)) void one(void) { asm volatile("nop"); }
__attribute__((noinline)) void two(void) { asm volatile("nop"); }
__attribute__((noinline)) void three(void) { asm volatile("nop"); }
__attribute__((noinline)) void transfer(void (*f)(void)) {
    asm volatile("mov %0, %%rax; call *%%rax" : : "r"(f) : "rax", "memory");
}
int main(void) {
    if (read(0, payload, 9) != 9) return 2;
    long n = 0;
    FILE *c = fopen("counter.state", "r");
    if (c) { fscanf(c, "%ld", &n); fclose(c); }
    c = fopen("counter.state", "w");
    if (c) { fprintf(c, "%ld\n", n + 1); fclose(c); }
    void (*targets[3])(void) = { one, two, three };
    transfer(targets[n % 3]);
    return 0;
}
'''


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gdb") and shutil.which("objdump"),
                     "requires gcc, gdb and objdump")
class ControlFlowTransferE2E(unittest.TestCase):
    def test_direct_producer_pass_and_scenario_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)
            binary = path / "control"
            (path / "control.c").write_text(SOURCE)
            subprocess.run(["gcc", "-g", "-O0", "-fno-pie", "-no-pie", "-o", str(binary),
                            str(path / "control.c")], check=True, capture_output=True, timeout=30)
            disasm = subprocess.check_output(["objdump", "-d", str(binary)], text=True, timeout=30)
            transfer_disasm = disasm.split("<transfer>:", 1)[1].split("\n\n", 1)[0]
            match = re.search(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+call\s+\*%rax\s*$", transfer_disasm, re.M)
            self.assertIsNotNone(match)
            breakpoint = "0x" + match.group(1)
            marker_address = subprocess.check_output(["nm", "-n", str(binary)], text=True, timeout=30)
            marker_address = "0x" + re.search(r"^([0-9a-f]+) B payload$", marker_address, re.M).group(1)
            first = path / "first.bin"
            second = path / "second.bin"
            first.write_bytes(b"AMARKER00")
            second.write_bytes(b"BMARKER00")
            def observe(mode, *options, input_path=None):
                cmd = [str(ROOT / "bin" / "rat-adapt"), "--root", str(path / ".rat"),
                       "--input", str(binary), "--direct-subject", str(binary),
                       "--proof", mode, "--proof-input", str(input_path or first),
                       "--proof-break", breakpoint, *options, "gdbq"]
                run = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
                return json.loads(run.stdout)["extensions"]["proof_observation"]["observation_id"]
            reg = observe("pwn-control-state")
            marker = observe("pwn-memory-control", "--proof-address", marker_address,
                             "--proof-marker", b"AMARKER00".hex())
            target = observe("pwn-control-transfer", "--proof-control-input", str(second),
                             "--proof-target-register", "$rax")
            bad_marker = subprocess.run(
                [str(ROOT / "bin" / "rat-adapt"), "--root", str(path / ".rat"),
                 "--input", str(binary), "--direct-subject", str(binary),
                 "--proof", "pwn-memory-control", "--proof-input", str(first),
                 "--proof-break", breakpoint, "--proof-address", marker_address,
                 "--proof-marker", b"NOTOWNED0".hex(), "gdbq"],
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(bad_marker.returncode, 0)
            self.assertIn("does not match the attacker marker", bad_marker.stderr)
            same_input = subprocess.run(
                [str(ROOT / "bin" / "rat-adapt"), "--root", str(path / ".rat"),
                 "--input", str(binary), "--direct-subject", str(binary),
                 "--proof", "pwn-control-transfer", "--proof-input", str(first),
                 "--proof-control-input", str(first), "--proof-break", breakpoint,
                 "--proof-target-register", "$rax", "gdbq"],
                capture_output=True, text=True, timeout=120)
            self.assertNotEqual(same_input.returncode, 0)
            self.assertIn("different bytes", same_input.stderr)
            stream = Stream(str(path))
            candidate = {"primitive_id":"control", "class":"control-flow", "status":"candidate",
                         "self_evidence":[], "input_digest":_file_digest(str(binary)),
                         "environment_digest":environment_fingerprint(), "revision":1}
            revise_primitive(stream, candidate)
            passed = {**candidate, "status":"pass", "revision":2,
                      "self_evidence":[reg, marker, target]}
            revise_primitive(stream, passed)
            self.assertEqual(stream.view()["primitives"]["control"]["status"], "pass")
            # A separately measured scenario cannot be spliced into this PASS.
            other = path / "other.bin"
            other.write_bytes(b"AMARKER00X")
            wrong_marker = observe("pwn-memory-control", "--proof-address", marker_address,
                                   "--proof-marker", b"AMARKER00".hex(), input_path=other)
            with self.assertRaisesRegex(ValueError, "same input and breakpoint scenario"):
                revise_primitive(stream, {**passed, "revision":3,
                                          "self_evidence":[reg, wrong_marker, target]})
            with self.assertRaisesRegex(ValueError, "environment_digest"):
                revise_primitive(stream, {**passed, "revision":3,
                                          "environment_digest":"sha256:"+"f"*64})
            stream.append("evidence.invalidated", {"observation_ids":[target],
                                                   "reason":"stale capture"})
            revise_primitive(stream, {**candidate, "primitive_id":"fresh"})
            with self.assertRaisesRegex(ValueError, "active direct SELF"):
                revise_primitive(stream, {**passed, "primitive_id":"fresh"})


    def test_external_counter_target_is_rejected(self):
        # The input reaches the binary but an external counter, not the input,
        # selects the transfer target.  Runs A/B/C therefore see three distinct
        # targets, so A != C and the producer must refuse to mint the proof.
        origin = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)
            binary = path / "counter"
            (path / "counter.c").write_text(COUNTER_SOURCE)
            subprocess.run(["gcc", "-g", "-O0", "-fno-pie", "-no-pie", "-o", str(binary),
                            str(path / "counter.c")], check=True, capture_output=True, timeout=30)
            disasm = subprocess.check_output(["objdump", "-d", str(binary)], text=True, timeout=30)
            transfer_disasm = disasm.split("<transfer>:", 1)[1].split("\n\n", 1)[0]
            match = re.search(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+call\s+\*%rax\s*$", transfer_disasm, re.M)
            self.assertIsNotNone(match)
            breakpoint = "0x" + match.group(1)
            first = path / "first.bin"
            second = path / "second.bin"
            first.write_bytes(b"AMARKER00")
            second.write_bytes(b"BMARKER00")
            os.chdir(directory)  # the inferior writes counter.state relative to cwd
            try:
                run = subprocess.run(
                    [str(ROOT / "bin" / "rat-adapt"), "--root", str(path / ".rat"),
                     "--input", str(binary), "--direct-subject", str(binary),
                     "--proof", "pwn-control-transfer", "--proof-input", str(first),
                     "--proof-control-input", str(second), "--proof-break", breakpoint,
                     "--proof-target-register", "$rax", "gdbq"],
                    capture_output=True, text=True, timeout=120)
            finally:
                os.chdir(origin)
            self.assertNotEqual(run.returncode, 0, run.stdout)
            self.assertIn("deterministically reproduce the target", run.stderr)


if __name__ == "__main__": unittest.main()
