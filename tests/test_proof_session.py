"""Real same-session leak -> payload -> transfer -> oracle -> typed PASS."""
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
from ratlib.proof_session import OUTPUT_CAP, decode_strategy, payload_for, parse_sessions
from ratlib.state_v2 import Stream, revise_primitive, environment_fingerprint, _file_digest

SOURCE = r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
char payload[17];
__attribute__((noinline)) void win(void) { puts("LOCAL_SUCCESS"); }
__attribute__((noinline)) void other(void) { puts("LOCAL_SUCCESS"); }
__attribute__((noinline)) void transfer(void (*f)(void)) {
  asm volatile("lea payload(%%rip), %%rsi; mov %0, %%rax; call *%%rax"
               : : "r"(f) : "rax", "rsi", "memory");
}
int main(void) {
  printf("WIN=%p\n", (void*)win); fflush(stdout);
  if (read(0, payload, sizeof payload) != sizeof payload) return 2;
  void (*f)(void); memcpy(&f, payload+9, 8); transfer(f); return 0;
}
'''

STRATEGY = {"schema":"rat.proof-session/v1", "leak_prefix":"WIN=",
            "prefix_hex":b"AMARKER00".hex(), "suffix_hex":"", "offset":0,
            "control_offset":16, "expect":"LOCAL_SUCCESS"}


class SessionValidation(unittest.TestCase):
    def test_rejects_unbounded_and_executable_strategies(self):
        for changes in ({"offset": True}, {"offset": 2**40}, {"prefix_hex":"00"*65},
                        {"leak_prefix":""}, {"schema":"other"}, {"command":"id"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decode_strategy(json.dumps({**STRATEGY, **changes}).encode())
        with self.assertRaises(ValueError):
            decode_strategy(b" "*8193)

    def test_capture_requires_own_leak_payload_normal_exit_and_oracle(self):
        leak=0x1234000
        data=b"WIN=0x1234000\nLOCAL_SUCCESS\n"
        record={"session_id":"a"*32,"label":"A","pid":123,"exit_code":0,
                "error":None,"leak":leak,"leak_line_hex":data.splitlines()[0].hex(),
                "payload_hex":payload_for(STRATEGY,leak).hex(),"stdout_hex":data.hex(),
                "pre_transfer_stdout_hex":data.split(b"\n",1)[0].hex()+"0a"}
        def text(r): return "RAT_SESSION_A="+json.dumps(r)+"\n"
        self.assertEqual(parse_sessions(text(record),STRATEGY,("A",)),[record])
        for changes in ({"payload_hex":payload_for(STRATEGY,leak+16).hex()},
                        {"leak":leak+16},{"exit_code":1},{"pid":None},
                        {"stdout_hex":b"WIN=0x1234000\nWRONG\n".hex()},
                        {"pre_transfer_stdout_hex":data.hex()}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_sessions(text({**record,**changes}),STRATEGY,("A",))

    def test_per_label_map_verifies_control_run_against_control_strategy(self):
        # The control run (B) must derive its payload from the control strategy
        # file, not the primary strategy with a label special-case.
        control={**STRATEGY,"offset":STRATEGY["control_offset"],"control_offset":STRATEGY["offset"]}
        strategies={"A":STRATEGY,"B":control,"C":STRATEGY}
        leak=0x1234000
        text=""
        for label,strat in (("A",STRATEGY),("B",control),("C",STRATEGY)):
            data=b"WIN=0x1234000\nLOCAL_SUCCESS\n"
            rec={"session_id":f"{label.lower()}{'0'*31}",
                 "label":label,"pid":100,"exit_code":0,"error":None,"leak":leak,
                 "leak_line_hex":data.splitlines()[0].hex(),
                 "payload_hex":payload_for(strat,leak).hex(),"stdout_hex":data.hex(),
                 "pre_transfer_stdout_hex":data.split(b"\n",1)[0].hex()+"0a"}
            text+="RAT_SESSION_"+label+"="+json.dumps(rec)+"\n"
        records=parse_sessions(text,strategies,("A","B","C"))
        self.assertEqual([r["label"] for r in records],["A","B","C"])
        # B verified against the primary strategy (wrong offset) must fail.
        with self.assertRaises(ValueError):
            parse_sessions(text,{"A":STRATEGY,"B":STRATEGY,"C":STRATEGY},("A","B","C"))


@unittest.skipUnless(sys.platform=="linux" and all(shutil.which(x) for x in ("gcc","gdb","objdump","nm")),
                     "Linux gcc/GDB required")
class SessionProofE2E(unittest.TestCase):
    def test_aslr_live_leak_pass_and_invalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            result = measure(pathlib.Path(directory))
            self.assertEqual(result["primitive"]["status"], "pass")
            self.assertEqual(len(result["primitive"]["self_evidence"]),3)
            records=result["transfer"]["value"]["sessions"]
            self.assertEqual([r["label"] for r in records],["A","B","C"])
            for record in records:
                self.assertEqual(record["exit_code"],0)
                self.assertGreater(record["pid"],0)
            # ASLR ON must produce a fresh leak per run; identical leaks across
            # A/B/C would mean the address did not randomize and the "same
            # session leak" claim is untested.  Preserve the observed leaks so
            # the documented three-distinct-address observation is a regression.
            leaks=[record["leak"] for record in records]
            self.assertEqual(len(set(leaks)),3,"ASLR ON must yield 3 distinct leaks")
            (pathlib.Path(directory)/"observed_leaks.json").write_text(
                json.dumps({"leaks_hex":[hex(x) for x in leaks],
                            "binary_sha256":result["binary_sha256"],
                            "strategy_sha256":result["strategy_sha256"]},sort_keys=True))
            stream=Stream(directory)
            stream.append("evidence.invalidated",{"observation_ids":[result["transfer"]["observation_id"]],
                                                  "reason":"stale session capture"})
            candidate={**result["primitive"],"primitive_id":"invalidated","status":"candidate",
                       "revision":1,"self_evidence":[]}
            revise_primitive(stream,candidate)
            with self.assertRaises(ValueError):
                revise_primitive(stream,{**candidate,"status":"pass","revision":2,
                                         "self_evidence":result["primitive"]["self_evidence"]})

    def test_decoy_marker_buffer_is_rejected(self):
        # Regression for the 2026-11-06 false positive: $rsi points at a decoy
        # buffer that holds only the fixed marker ("AMARKER00") while the real
        # leak-derived payload lives elsewhere.  The transfer still uses the
        # real payload, but memory-control now reads the FULL payload length at
        # $rsi, so the decoy (no dynamic target bytes) must be rejected rather
        # than yielding a typed PASS.
        decoy_source=SOURCE.replace(
            "char payload[17];",
            'char payload[17];\nchar decoy[17] = "AMARKER00";').replace(
            "lea payload(%%rip), %%rsi", "lea decoy(%%rip), %%rsi")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError) as context:
                measure(pathlib.Path(directory),source=decoy_source)
            self.assertIn("session leak-derived payload",str(context.exception))

    def test_large_output_before_oracle_still_proves(self):
        # Regression for M1: a benign binary that prints more than the old
        # 64 KiB RLIMIT_FSIZE cap *before* the success oracle was killed with
        # SIGXFSZ (non-zero exit) and its proof rejected, even though the leak,
        # the leak-derived transfer and the oracle were all correct.  Emit a
        # ~70 KiB banner after the first-line leak but before the controlled
        # read, so the capture crosses the old cap; with OUTPUT_CAP raised the
        # inferior runs to completion and the typed PASS must still be produced.
        banner_bytes = 70000  # > the retired 65536-byte cap
        banner_loop = ("\n  for (int _i = 0; _i < " + str(banner_bytes)
                       + "; _i++) putchar(0x2e);\n  fflush(stdout);")
        big_source = SOURCE.replace(
            'printf("WIN=%p\\n", (void*)win); fflush(stdout);',
            'printf("WIN=%p\\n", (void*)win); fflush(stdout);' + banner_loop)
        with tempfile.TemporaryDirectory() as directory:
            result = measure(pathlib.Path(directory), source=big_source)
            self.assertEqual(result["primitive"]["status"], "pass")
            self.assertEqual(len(result["primitive"]["self_evidence"]), 3)
            records = result["transfer"]["value"]["sessions"]
            for record in records:
                self.assertEqual(record["exit_code"], 0, "inferior must exit normally, not SIGXFSZ")
                self.assertGreater(record["pid"], 0)
                # The banner really did cross the retired 64 KiB cap, so this
                # PASS exercises the raised bound, not a short-output path.
                captured = bytes.fromhex(record["stdout_hex"])
                self.assertGreater(len(captured), 65536,
                                   "captured output must exceed the old cap to be a real regression")
                self.assertEqual(captured.count(0x2e), banner_bytes)
                self.assertIn(b"LOCAL_SUCCESS", captured)

    def test_slow_first_leak_within_proof_timeout_still_proves(self):
        # NB: this E2E really sleeps >5s per inferior, so it is one of the slower
        # tests in the suite.  It is intentionally NOT env-gated: the core-e2e
        # coverage guard (tests/test_core_e2e_coverage_guard.py) requires every
        # SessionProofE2E method to run whenever the toolchain is present, so a
        # skip here would make the guard fail loudly rather than quietly drop this
        # regression.  Keep it runnable.
        # Regression: the leak feeder used a hardcoded 5s deadline (started at
        # Session construction, before `run`), so a binary whose time-to-first-leak
        # exceeded 5s was rejected with "session leak timeout" even though the whole
        # proof run is bounded by rat-adapt's much larger --timeout.  The window is
        # now sized to that budget (LEAK_WAIT_SECONDS), so a ~6s delay before the
        # leak -- comfortably over the retired 5s -- must still PASS.  The default
        # rat-adapt --timeout (60s) is the real bound and is not exceeded.
        delay_seconds = 6  # > the retired hardcoded 5s feeder deadline
        slow_source = (SOURCE
            .replace("#include <unistd.h>", "#include <unistd.h>\n#include <time.h>")
            .replace('printf("WIN=%p\\n", (void*)win); fflush(stdout);',
                     'nanosleep(&(struct timespec){.tv_sec = ' + str(delay_seconds)
                     + '}, NULL);\n  printf("WIN=%p\\n", (void*)win); fflush(stdout);'))
        with tempfile.TemporaryDirectory() as directory:
            result = measure(pathlib.Path(directory), source=slow_source)
            self.assertEqual(result["primitive"]["status"], "pass")
            self.assertEqual(len(result["primitive"]["self_evidence"]), 3)
            for record in result["transfer"]["value"]["sessions"]:
                self.assertIsNone(record["error"], "a slow-but-bounded leak must not time out")
                self.assertEqual(record["exit_code"], 0)
                self.assertIn(b"LOCAL_SUCCESS", bytes.fromhex(record["stdout_hex"]))

    def test_unrelated_large_scratch_file_still_proves(self):
        # Regression: the feeder imposed a process-wide RLIMIT_FSIZE(OUTPUT_CAP)
        # that the inferior inherited, so a target writing more than OUTPUT_CAP to
        # an UNRELATED scratch file (not the stdout capture) was killed with
        # SIGXFSZ -> non-zero exit -> the proof was rejected even though the leak,
        # the leak-derived transfer and the oracle were all valid.  With the limit
        # removed, the inferior may write a large scratch file and still PASS; the
        # capture bound now lives only on the read side (OUTPUT_CAP checks).  The
        # scratch write (~5 MiB > the 4 MiB OUTPUT_CAP) happens after the leak but
        # before the controlled read, and goes to a file in the cwd, never stdout,
        # so the captured stdout stays tiny.
        # The runner spawns the inferior with a minimal environment that keeps only
        # an allowlist (PATH/LANG/.../TMPDIR), so the scratch path is derived from
        # TMPDIR, which we point at a dedicated directory for this run.
        scratch_write = (
            '\n  { const char *_t = getenv("TMPDIR"); char _path[4096];'
            ' snprintf(_path, sizeof _path, "%s/rat_scratch.bin", _t ? _t : "/tmp");'
            ' FILE *_s = fopen(_path, "wb");'
            ' if (_s) { char _b[65536]; memset(_b, 0x5a, sizeof _b);'
            ' for (int _i = 0; _i < 80; _i++) fwrite(_b, 1, sizeof _b, _s);'
            ' fclose(_s); } }\n')  # 80 * 64 KiB = 5 MiB > OUTPUT_CAP (4 MiB)
        scratch_source = (SOURCE
            .replace("#include <unistd.h>", "#include <unistd.h>\n#include <stdlib.h>")
            .replace('printf("WIN=%p\\n", (void*)win); fflush(stdout);',
                     'printf("WIN=%p\\n", (void*)win); fflush(stdout);' + scratch_write))
        with tempfile.TemporaryDirectory() as directory, \
                tempfile.TemporaryDirectory() as scratch_tmp:
            scratch = pathlib.Path(scratch_tmp) / "rat_scratch.bin"
            old_env = os.environ.get("TMPDIR")
            os.environ["TMPDIR"] = scratch_tmp
            try:
                result = measure(pathlib.Path(directory), source=scratch_source)
            finally:
                if old_env is None:
                    os.environ.pop("TMPDIR", None)
                else:
                    os.environ["TMPDIR"] = old_env
            self.assertEqual(result["primitive"]["status"], "pass")
            self.assertEqual(len(result["primitive"]["self_evidence"]), 3)
            records = result["transfer"]["value"]["sessions"]
            for record in records:
                self.assertEqual(record["exit_code"], 0,
                                 "inferior must exit normally, not SIGXFSZ on an unrelated write")
                self.assertGreater(record["pid"], 0)
                captured = bytes.fromhex(record["stdout_hex"])
                # The large data went to the scratch file, not stdout, so the
                # captured output stays small and still carries the oracle.
                self.assertLess(len(captured), 4096)
                self.assertIn(b"LOCAL_SUCCESS", captured)
            # The scratch file really did exceed OUTPUT_CAP, so this PASS exercises
            # the removed process-wide write limit, not a small-write path.
            self.assertTrue(scratch.is_file(), "inferior must have written the scratch file")
            self.assertGreater(scratch.stat().st_size, OUTPUT_CAP)

    def test_mixed_concrete_and_session_input_kind_is_rejected(self):
        # The slots of a control-flow PASS must all be session-strategy or all
        # concrete; a mix is rejected (state_v2.py input_kind gate).  Build a
        # real all-session stream on disk, then forge EVERY slot observation's
        # recorded scenario.input_kind to the concrete value (None) -- keeping
        # the per-slot scenarios identical so the same-scenario check passes --
        # while the evidence envelopes still declare session=True.  That is the
        # concrete-claim / session-envelope mix the input_kind gate must catch;
        # validate_history re-runs the same gate the local write path uses.
        from ratlib.state_v2 import validate_history
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = measure(root)
            forged_oids = set(result["evidence"])
            stream = Stream(str(root))
            events = stream.read()
            touched = 0
            for event in events:
                if (event["type"] == "observation.recorded"
                        and event["payload"].get("observation_id") in forged_oids):
                    scenario = (event["payload"].setdefault("extensions", {})
                                .setdefault("scenario", {}))
                    self.assertEqual(scenario.get("input_kind"), "session-strategy/v1")
                    scenario["input_kind"] = None  # claim concrete while envelopes are session
                    touched += 1
            self.assertEqual(touched, 3, "expected three slot observations to forge")
            with self.assertRaisesRegex(ValueError,
                    "mixes concrete input and session strategy"):
                validate_history(events, str(root), artifact_root=stream.root)


def measure(path, source=SOURCE):
    (path/"control.c").write_text(source)
    binary=path/"control"
    subprocess.run(["gcc","-g","-O0","-fpie","-pie","-o",str(binary),str(path/"control.c")],
                   check=True,capture_output=True,timeout=30)
    symbols={parts[2]:int(parts[0],16) for line in subprocess.check_output(["nm",str(binary)],text=True).splitlines()
             if len(parts:=line.split())==3 and parts[1] in {"T","t"}}
    block=subprocess.check_output(["objdump","-d",str(binary)],text=True).split("<transfer>:",1)[1].split("\n\n",1)[0]
    addr=int(re.search(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+call\s+\*%rax\s*$",block,re.M).group(1),16)
    breakpoint="transfer+0x%x" % (addr-symbols["transfer"])
    strategy={**STRATEGY,"control_offset":symbols["other"]-symbols["win"]}
    primary=path/"primary.json"; control=path/"control.json"
    primary.write_text(json.dumps(strategy))
    control.write_text(json.dumps({**strategy,"offset":strategy["control_offset"],"control_offset":0}))
    evidence=[]; observations=[]
    for mode,options in (
        ("pwn-control-transfer",["--proof-control-input",str(control),"--proof-target-register","$rax"]),
        ("pwn-control-state",[]),
        ("pwn-memory-control",["--proof-address","$rsi","--proof-marker",STRATEGY["prefix_hex"]]),
    ):
        cmd=[str(ROOT/"bin/rat-adapt"),"--root",str(path/".rat"),"--input",str(binary),
             "--direct-subject",str(binary),"--proof",mode,"--proof-input",str(primary),
             "--proof-break",breakpoint,"--proof-aslr","on","--proof-session",*options,"gdbq"]
        run=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
        (path/(mode+".log")).write_text(json.dumps({"command":cmd,"rc":run.returncode,"out":run.stdout,"err":run.stderr}))
        if run.returncode: raise RuntimeError(run.stderr+run.stdout)
        evidence.append(json.loads(run.stdout)["extensions"]["proof_observation"]["observation_id"])
    stream=Stream(str(path))
    candidate={"primitive_id":"same-session","class":"control-flow","status":"candidate",
               "self_evidence":[],"input_digest":_file_digest(str(binary)),
               "environment_digest":environment_fingerprint(),"revision":1}
    revise_primitive(stream,candidate)
    revise_primitive(stream,{**candidate,"status":"pass","self_evidence":evidence,"revision":2})
    view=stream.view()
    return {"primitive":view["primitives"]["same-session"],"transfer":view["observations"][evidence[0]],
            "evidence":evidence,"observations":view["observations"],"root":str(path),
            "binary_sha256":_file_digest(str(binary)),"strategy_sha256":_file_digest(str(primary))}
