import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "pwn" / "stack_overflow.c"


class LocalPwnToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.binary = pathlib.Path(self.temp.name) / "stack_overflow"
        built = subprocess.run(
            ["cc", "-fno-stack-protector", "-no-pie", "-O0", "-o", str(self.binary), str(FIXTURE)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(built.returncode, 0, built.stderr)

    def tearDown(self):
        self.temp.cleanup()

    def tool(self, name, *args, check=True):
        result = subprocess.run(
            [str(ROOT / "bin" / name), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if check and result.returncode != 0:
            self.fail(result.stderr or result.stdout)
        return result

    def test_pwnleak_classifies_and_rejects_markers(self):
        result = self.tool(
            "pwnleak", "--text", "leak=0x7ffff7a5f980 marker=0x4141414141414141", "--json"
        )
        candidates = json.loads(result.stdout)["candidates"]
        self.assertEqual(candidates[0]["classification"], ["shared-library"])
        self.assertEqual(candidates[0]["disposition"], "candidate")
        self.assertEqual(candidates[1]["disposition"], "reject")

    def test_pwnleak_unpack_raw_pointer(self):
        result = self.tool("pwnleak", "--bytes", "7856341200000000", "--json")
        candidate = json.loads(result.stdout)["candidates"][0]
        self.assertEqual(candidate["value"], 0x12345678)
        self.assertEqual(candidate["byte_offset"], 0)

    def test_pwnleak_classifies_arm_kernel_pointer(self):
        result = self.tool("pwnleak", "--text", "0x8000e348", "--bits", "32", "--arch", "arm", "--json")
        self.assertEqual(json.loads(result.stdout)["candidates"][0]["classification"], ["kernel"])

    def test_pwnpayload_detects_newline_and_consumer_truncation(self):
        result = self.tool(
            "pwnpayload", "--hex", "414141410a4242", "--bad-byte", "newline", "--consumer", "gets", "--json", check=False
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["verdict"], "fail")
        self.assertEqual(report["consumer_effect"]["bytes_consumed"], 4)

    def test_pwnpayload_sendline_is_checked(self):
        result = self.tool("pwnpayload", "--hex", "4141", "--bad-byte", "newline", "--transport", "sendline", "--json", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("sendline appends a prohibited newline", json.loads(result.stdout)["errors"])

    def test_pwnpayload_truncation_fails_without_bad_byte_rule(self):
        result = self.tool("pwnpayload", "--hex", "41410a4242", "--consumer", "gets", "--json", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("consumer stops before the transmitted payload ends", json.loads(result.stdout)["errors"])

    def test_pwnpayload_can_explicitly_allow_truncation(self):
        result = self.tool("pwnpayload", "--hex", "41410a4242", "--consumer", "gets", "--allow-truncation", "--json")
        self.assertIn("consumer stops before the transmitted payload ends", json.loads(result.stdout)["warnings"])

    def test_pwnropcheck_validates_mapped_call_and_alignment(self):
        main = json.loads(self.tool("pwncalc", "--json", "elf-offset", "--elf", str(self.binary), "--symbol", "main").stdout)["result"]["offset"]
        chain = pathlib.Path(self.temp.name) / "chain.json"
        chain.write_text(json.dumps({"initial_rsp_mod16": 0, "entries": [{"kind": "call", "name": "main", "value": main}]}))
        result = self.tool("pwnropcheck", "--file", str(chain), "--map", "%s@0" % self.binary, "--json")
        report = json.loads(result.stdout)
        self.assertEqual(report["verdict"], "pass")
        self.assertTrue(report["entries"][0]["executable"])
        self.assertEqual(report["entries"][0]["rsp_mod16_at_entry"], 8)

    def test_pwnropcheck_rejects_mapping_bitness_mismatch(self):
        main = json.loads(self.tool("pwncalc", "--json", "elf-offset", "--elf", str(self.binary), "--symbol", "main").stdout)["result"]["offset"]
        chain = pathlib.Path(self.temp.name) / "chain32.json"
        chain.write_text(json.dumps({"entries": [{"kind": "call", "name": "main", "value": main}]}))
        result = self.tool("pwnropcheck", "--file", str(chain), "--map", "%s@0" % self.binary, "--bits", "32", "--json", check=False)
        report = json.loads(result.stdout)
        self.assertEqual(report["verdict"], "fail")
        self.assertIn("mapping bitness does not match --bits", "\n".join(report["errors"]))

    def test_pwnropcheck_rejects_word_overflow_without_traceback(self):
        result = self.tool("pwnropcheck", "--chain", "0x100000000", "--bits", "32", "--json", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside the selected word size", "\n".join(json.loads(result.stdout)["errors"]))

    def test_pwncrash_reproduces_local_core_evidence(self):
        # stack_overflow.c is a plain return-address overwrite: the corrupted
        # return address is (virtually always) non-canonical, so `ret` faults
        # as a #GP rather than a #PF. On x86_64 a #GP carries no linear fault
        # address, so the kernel reports siginfo si_addr=0 -- core.fault_addr
        # (and therefore fault_cyclic_offset) is legitimately null for this
        # crash class on any x86_64 Linux, emulated or native.
        #
        # Which register holds the controlled value in the core is NOT
        # portable: some kernels snapshot RIP as the popped controlled value
        # (pc_cyclic_offset == 72), others snapshot the faulting `ret`
        # instruction address (pc_cyclic_offset is null). pwncrash therefore
        # exposes control_cyclic_offset, which falls back to the popped return
        # slot at [sp-8] -- program memory that reads back the controlled
        # value identically on every x86_64 Linux. That is the honest,
        # environment-independent RIP-hijack evidence.
        result = self.tool("pwncrash", str(self.binary), "--pattern-length", "256", "--repetitions", "2", "--json")
        report = json.loads(result.stdout)
        self.assertEqual(report["verdict"], "crash-reproduced")
        self.assertEqual(report["stable_signal"], 11)
        self.assertEqual(report["core"]["control_cyclic_offset"], 72)
        self.assertEqual(report["core"]["fault_addr"], 0)
        self.assertEqual(report["promotion"], "candidate-evidence-only")


if __name__ == "__main__":
    unittest.main()
