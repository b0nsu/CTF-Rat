"""Paired local ASLR experiment; run with --write-result PATH to retain raw runs.

Each layer compares three conditions on one fixture build. The two layers use
different programs and timeouts:

* ``measure()`` is the *runtime exploit-outcome* layer.  It fires a control
  target at an indirect call and classifies each run as success or
  ``exploit-failed`` from the raw return code and stdout.
* ``gate_measure()`` is the *proof-gate* layer.  It drives the real
  ``control-flow/v2`` producer (``rat-adapt --proof pwn-control-transfer``)
  under each ASLR condition and records whether the canonical proof could be
  *produced* at all.  Its successful ASLR-on case uses a GDB symbol-relative
  breakpoint; that tests debugger resolution, not an attacker-obtained leak.
  A stale absolute address is ``proof-blocked`` -- distinct from a
  produced-then-crashing exploit.  This keeps proof absence and exploit failure
  as separate stages.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


SOURCE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((noinline)) static void win(void) { puts("LOCAL_SUCCESS"); }
int main(void) {
    if (getenv("RAT_LEAK")) { printf("WIN=%p\n", (void *)win); fflush(stdout); }
    uintptr_t target = 0;
    if (read(0, &target, sizeof(target)) != sizeof(target)) return 3;
    ((void (*)(void))target)();
    return 0;
}
'''


def _run(argv, payload, env, *, label):
    process = subprocess.run(argv, input=payload, capture_output=True, timeout=5, env=env)
    return {"label": label, "argv": argv, "input_hex": payload.hex(),
            "returncode": process.returncode,
            "stdout": process.stdout.decode(errors="replace"),
            "stderr": process.stderr.decode(errors="replace")}


def measure(directory):
    directory = pathlib.Path(directory)
    source = directory / "aslr_probe.c"
    binary = directory / "aslr_probe"
    source.write_text(SOURCE)
    compiler = subprocess.run(["gcc", "-g", "-O0", "-fpie", "-pie", "-o", str(binary), str(source)],
                              capture_output=True, text=True, timeout=30)
    if compiler.returncode:
        raise RuntimeError("fixture compile failed: " + compiler.stderr)
    off = ["setarch", platform.machine(), "-R", str(binary)]
    on = [str(binary)]
    base_env = dict(os.environ)
    leak_env = dict(base_env, RAT_LEAK="1")
    reference = _run(off, b"", leak_env, label="aslr-off-reference")
    if not reference["stdout"].startswith("WIN=0x"):
        raise RuntimeError("ASLR OFF unavailable: " + json.dumps(reference))
    fixed = int(reference["stdout"].splitlines()[0].split("=", 1)[1], 16)
    off_case = _run(off, struct.pack("<Q", fixed), base_env, label="aslr-off-fixed-address")
    process = subprocess.Popen(on, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=leak_env)
    try:
        leak_line = process.stdout.readline()
        if not leak_line.startswith(b"WIN=0x"):
            raise RuntimeError("same-session leak unavailable: " + repr(leak_line))
        live = int(leak_line.strip().split(b"=", 1)[1], 16)
        rest, stderr = process.communicate(struct.pack("<Q", live), timeout=5)
    except BaseException:
        process.kill()
        process.communicate()
        raise
    stable_case = {"label": "aslr-on-same-session-leak", "argv": on,
                   "input_hex": struct.pack("<Q", live).hex(), "leak_line": leak_line.decode(),
                   "returncode": process.returncode, "stdout": rest.decode(errors="replace"),
                   "stderr": stderr.decode(errors="replace")}
    limited_case = _run(on, struct.pack("<Q", fixed), base_env,
                        label="aslr-on-stale-off-session-address")
    cases = [off_case, stable_case, limited_case]
    for case in cases:
        success = case["returncode"] == 0 and "LOCAL_SUCCESS" in case["stdout"]
        case["success"] = success
        case["failure_stage"] = None if success else "exploit-failed"
    return {"schema": "rat.aslr-paired-experiment/v1",
            "fixture_sha256": "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_sha256": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
            "environment": {"architecture": platform.machine(),
                            "libc": platform.libc_ver(),
                            "loader": os.path.realpath("/lib64/ld-linux-x86-64.so.2"),
                            "stdio": "stdin/stdout/stderr pipes", "timeout_seconds": 5},
            "reference": reference, "cases": cases}


# Real indirect transfer (`call *%rax`) the control-flow/v2 producer measures.
# Shared with the control-flow transfer e2e so both exercise the same gate.
GATE_SOURCE = r'''
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


def _transfer_breakpoint(binary):
    disasm = subprocess.check_output(["objdump", "-d", str(binary)], text=True)
    block = disasm.split("<transfer>:", 1)[1].split("\n\n", 1)[0]
    match = re.search(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+call\s+\*%rax\s*$", block, re.M)
    if not match:
        raise RuntimeError("transfer breakpoint not found in disassembly")
    return "0x" + match.group(1)


def _gate_observe(path, binary, breakpoint, aslr, first, second):
    """Drive the real control-flow/v2 producer; return (ok, stage, detail)."""
    cmd = [str(ROOT / "bin" / "rat-adapt"), "--root", str(path / ".rat"),
           "--input", str(binary), "--direct-subject", str(binary),
           "--proof", "pwn-control-transfer", "--proof-input", str(first),
           "--proof-control-input", str(second), "--proof-break", breakpoint,
           "--proof-target-register", "$rax", "--proof-aslr", aslr, "gdbq"]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if run.returncode == 0:
        try:
            observation = json.loads(run.stdout)["extensions"]["proof_observation"]
        except (ValueError, KeyError) as exc:  # pragma: no cover - defensive
            return False, "proof-blocked", "proof output not parseable: %s" % exc
        return True, None, observation["observation_id"]
    # A refusal to mint the canonical observation is a blocked proof, not a run
    # that executed and crashed.  rat-adapt reports the gate reason on stderr.
    return False, "proof-blocked", run.stderr.strip().splitlines()[-1] if run.stderr.strip() else "gate refused"


def gate_measure(directory):
    """Compare proof producibility across ASLR conditions on one build."""
    directory = pathlib.Path(directory)
    source = directory / "control.c"
    binary = directory / "control"
    source.write_text(GATE_SOURCE)
    # PIE so a stale absolute breakpoint does not resolve under ASLR.
    compile_pie = subprocess.run(
        ["gcc", "-g", "-O0", "-fpie", "-pie", "-o", str(binary), str(source)],
        capture_output=True, text=True, timeout=30)
    if compile_pie.returncode:
        raise RuntimeError("gate fixture compile failed: " + compile_pie.stderr)
    first = directory / "first.bin"
    second = directory / "second.bin"
    first.write_bytes(b"AMARKER00")
    second.write_bytes(b"BMARKER00")

    cases = []

    # Under ASLR OFF, a breakpoint measured in one debugger run is reusable.
    # Under ASLR ON, the same absolute address becomes stale in the producer's
    # separate run.
    deterministic_break = _gdb_transfer_breakpoint(binary, "off")

    # (1) ASLR OFF: the deterministic address resolves, so the producer mints a
    # valid control-flow/v2 observation -> success, no failure stage.
    off_dir = directory / "aslr-off"
    off_dir.mkdir()
    ok, stage, detail = _gate_observe(off_dir, binary, deterministic_break, "off", first, second)
    cases.append({"label": "gate-aslr-off", "aslr": "off", "breakpoint": deterministic_break,
                  "success": ok, "failure_stage": stage, "detail": detail})

    # (2) ASLR ON + debugger symbol resolution: GDB resolves the call-site
    # (`transfer+off`) inside the producer's run. This proves the gate can
    # observe a randomized process when it knows the symbol, not that an
    # attacker obtained a same-session leak.
    callsite_offset = int(_transfer_breakpoint(binary), 16) - _static_transfer_symbol(binary)
    symbol_break = "transfer+0x%x" % callsite_offset
    stable_dir = directory / "aslr-on-symbol-resolved"
    stable_dir.mkdir()
    ok, stage, detail = _gate_observe(stable_dir, binary, symbol_break, "on", first, second)
    cases.append({"label": "gate-aslr-on-symbol-resolved-breakpoint", "aslr": "on",
                  "breakpoint": symbol_break, "success": ok, "failure_stage": stage,
                  "detail": detail})

    # (3) ASLR ON + limited information: the only address known is the one from a
    # prior (non-randomized or foreign) session, with no symbol resolution.
    # Under real randomization it does not resolve, so the canonical proof
    # cannot be produced at all.  This is proof-blocked because the gate
    # refuses before any exploit is attempted.
    blocked_dir = directory / "aslr-on-limited"
    blocked_dir.mkdir()
    ok, stage, detail = _gate_observe(blocked_dir, binary, deterministic_break, "on", first, second)
    cases.append({"label": "gate-aslr-on-limited-information", "aslr": "on",
                  "breakpoint": deterministic_break, "success": ok, "failure_stage": stage,
                  "detail": detail})

    return {"schema": "rat.aslr-proof-gate-experiment/v1",
            "fixture_sha256": "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_sha256": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
            "environment": {"architecture": platform.machine(),
                            "libc": platform.libc_ver(),
                            "loader": os.path.realpath("/lib64/ld-linux-x86-64.so.2"),
                            "stdio": "stdin/stdout/stderr pipes", "timeout_seconds": 120},
            "cases": cases}


def _static_transfer_symbol(binary):
    for line in subprocess.check_output(["nm", str(binary)], text=True).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "transfer" and parts[1] in ("T", "t"):
            return int(parts[0], 16)
    raise RuntimeError("transfer symbol not found")


def _gdb_transfer_breakpoint(binary, aslr):
    """Measure the runtime call *%rax address through GDB.

    GDB runs the inferior (randomization per ``aslr``) and prints the live
    ``&transfer``.  The call-site breakpoint is at a fixed offset inside
    ``transfer``, so the live breakpoint is ``live_transfer + (bp - transfer)``
    computed from the static symbol and disassembly offsets. This is debugger
    introspection, and does not establish an attacker-visible leak.
    """
    gdb = subprocess.run(
        ["gdb", "-q", "-batch",
         "-ex", "set disable-randomization " + ("off" if aslr == "on" else "on"),
         "-ex", "break transfer", "-ex", "run",
         "-ex", "printf \"RAT_LIVE=0x%lx\\n\", (unsigned long)&transfer",
         str(binary)],
        input=b"AMARKER00", capture_output=True, timeout=30)
    match = re.search(r"RAT_LIVE=0x([0-9a-fA-F]+)", gdb.stdout.decode(errors="replace"))
    if not match:
        raise RuntimeError("GDB transfer address unavailable: " + gdb.stdout.decode(errors="replace"))
    offset = int(_transfer_breakpoint(binary), 16) - _static_transfer_symbol(binary)
    return "0x%x" % (int(match.group(1), 16) + offset)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64"
                     and shutil.which("gcc") and shutil.which("setarch"),
                     "Linux x86-64, gcc and setarch required")
class ASLRControlFlowExperiment(unittest.TestCase):
    def test_paired_runtime_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            result = measure(directory)
        off, stable, limited = result["cases"]
        self.assertTrue(off["success"], off)
        self.assertTrue(stable["success"], stable)
        self.assertFalse(limited["success"], limited)
        self.assertEqual(limited["failure_stage"], "exploit-failed")
        self.assertNotEqual(off["input_hex"], stable["input_hex"])


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64"
                     and shutil.which("gcc") and shutil.which("gdb")
                     and shutil.which("objdump") and shutil.which("nm"),
                     "Linux x86-64, gcc, gdb, objdump and nm required")
class ASLRProofGateExperiment(unittest.TestCase):
    def test_proof_blocked_is_distinct_from_exploit_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = gate_measure(directory)
        with tempfile.TemporaryDirectory() as runtime_dir:
            runtime = measure(runtime_dir)
        off, stable, limited = result["cases"]
        # One build (same fixture_sha256) carries all three ASLR conditions.
        self.assertEqual(off["aslr"], "off")
        self.assertEqual(stable["aslr"], "on")
        self.assertEqual(limited["aslr"], "on")
        # ASLR OFF: the deterministic address resolves, so the canonical
        # control-flow/v2 proof is produced -> success, no failure stage.
        self.assertTrue(off["success"], off)
        self.assertIsNone(off["failure_stage"], off)
        # ASLR ON + GDB symbol resolution: the symbol-relative call-site is
        # resolved inside the producer's own session.
        self.assertTrue(stable["success"], stable)
        self.assertIsNone(stable["failure_stage"], stable)
        # ASLR ON + limited information: a stale cross-session address no longer
        # resolves, so the proof itself cannot be produced.  It must be
        # proof-blocked, never exploit-failed -- the gate refused before any
        # exploit ran.
        self.assertFalse(limited["success"], limited)
        self.assertEqual(limited["failure_stage"], "proof-blocked", limited)
        self.assertIn("did not stop at the requested proof breakpoint",
                      limited["detail"])
        # The symbol-resolved and limited-information cases differ in how the
        # breakpoint is specified; reusing the stale absolute one is refused.
        self.assertNotEqual(stable["breakpoint"], limited["breakpoint"])
        # The gate layer surfaces proof-blocked; the runtime layer above
        # surfaces exploit-failed.  Neither label leaks into the other.
        stages = {case["failure_stage"] for case in result["cases"]}
        self.assertIn("proof-blocked", stages)
        self.assertNotIn("exploit-failed", stages)
        runtime_stages = {case["failure_stage"] for case in runtime["cases"]}
        self.assertIn("exploit-failed", runtime_stages)
        self.assertNotIn("proof-blocked", runtime_stages)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-result")
    parser.add_argument("--write-gate-result")
    arguments = parser.parse_args()
    if arguments.write_result or arguments.write_gate_result:
        if arguments.write_result:
            with tempfile.TemporaryDirectory() as directory:
                result = measure(directory)
            pathlib.Path(arguments.write_result).write_text(json.dumps(result, indent=2) + "\n")
            print(arguments.write_result)
        if arguments.write_gate_result:
            with tempfile.TemporaryDirectory() as directory:
                gate = gate_measure(directory)
            pathlib.Path(arguments.write_gate_result).write_text(json.dumps(gate, indent=2) + "\n")
            print(arguments.write_gate_result)
    else:
        unittest.main(argv=[__file__])
