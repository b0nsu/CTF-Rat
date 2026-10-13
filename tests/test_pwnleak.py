import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LEAK = bytes.fromhex("10c3dc69877f")


class PwnLeakPartialTests(unittest.TestCase):
    def tool(self, *args, data=None):
        return subprocess.run(
            [str(ROOT / "bin" / "pwnleak"), *args],
            input=data, capture_output=True, cwd=ROOT,
        )

    def report(self, *args, data=None):
        result = self.tool(*args, "--json", data=data)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_six_byte_libc_leak(self):
        report = self.report("--bytes", LEAK.hex(), "--partial")
        self.assertEqual(report["candidate_count"], 1)
        item = report["candidates"][0]
        self.assertEqual(item["value"], 0x7F8769DCC310)
        self.assertEqual(item["classification"], ["shared-library"])
        self.assertEqual(item["disposition"], "candidate")
        self.assertEqual(item["text"], LEAK.hex())
        self.assertEqual(item["byte_offset"], 0)
        self.assertEqual(item["observed_byte_count"], 6)
        self.assertEqual(item["missing_byte_count"], 2)
        self.assertEqual(item["completion_assumption"], "zero-extension")

    def test_partial_requires_opt_in(self):
        for args, data in [(("--bytes", LEAK.hex()), None), (("--raw",), LEAK)]:
            with self.subTest(args=args):
                result = self.tool(*args, "--json", data=data)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"need at least 8 packed bytes", result.stderr)

    def test_all_partial_lengths_preserve_observed_bytes(self):
        raw = bytes.fromhex("10325476987f00")
        for count in range(1, 8):
            with self.subTest(count=count):
                item = self.report("--bytes", raw[:count].hex(), "--partial")["candidates"][0]
                self.assertEqual(item["value"], int.from_bytes(raw[:count], "little"))
                self.assertEqual(item["text"], raw[:count].hex())
                self.assertEqual(item["observed_byte_count"], count)
                self.assertEqual(item["missing_byte_count"], 8 - count)
                self.assertEqual(item["completion_assumption"], "zero-extension")

    def test_raw_stdin(self):
        self.assertEqual(
            self.report("--raw", "--partial", data=LEAK),
            self.report("--bytes", LEAK.hex(), "--partial"),
        )

    def test_raw_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "leak.bin"
            path.write_bytes(LEAK)
            self.assertEqual(
                self.report("--file", str(path), "--raw", "--partial"),
                self.report("--bytes", LEAK.hex(), "--partial"),
            )

    def test_empty_and_multiple_pointer_inputs_rejected(self):
        for raw in [b"", LEAK + b"\0" * 3, LEAK * 2, b"\0" * 16]:
            for source in ["bytes", "stdin"]:
                with self.subTest(length=len(raw), source=source):
                    result = (self.tool("--bytes", raw.hex(), "--partial") if source == "bytes"
                              else self.tool("--raw", "--partial", data=raw))
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(b"exactly one pointer of 1-8 observed bytes", result.stderr)

    def test_unsupported_profiles_rejected(self):
        profiles = [
            ("--bits", "32"), ("--width", "4"), ("--endian", "big"),
            ("--arch", "arm"), ("--arch", "aarch64"), ("--arch", "generic"),
        ]
        for profile in profiles:
            with self.subTest(profile=profile):
                result = self.tool("--bytes", LEAK.hex(), "--partial", *profile)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"requires 64-bit x86, little-endian, width 8", result.stderr)

    def test_explicit_supported_profile(self):
        report = self.report("--bytes", LEAK.hex(), "--partial", "--arch", "x86", "--width", "8")
        self.assertEqual(report["arch"], "x86")
        self.assertIsNone(report["profile_assumption"])
        self.assertEqual(report["candidates"][0]["value"], 0x7F8769DCC310)

    def test_text_inputs_rejected(self):
        for args in [(), ("--text", "0x7f8769dcc310"), ("--text", "abc", "--raw")]:
            with self.subTest(args=args):
                result = self.tool("--partial", *args, data=b"0x7f8769dcc310")
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"requires --bytes or --raw file/stdin input", result.stderr)

    def test_complete_pointer_unchanged(self):
        full = (LEAK + b"\0\0").hex()
        report = self.report("--bytes", full)
        self.assertEqual(report, self.report("--bytes", full, "--partial"))
        self.assertNotIn("completion_assumption", report["candidates"][0])

    def test_default_multi_pointer_unpacking_unchanged(self):
        full = LEAK + b"\0\0"
        report = self.report("--raw", data=full * 2)
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual([item["byte_offset"] for item in report["candidates"]], [0, 8])
        self.assertTrue(all(item["value"] == 0x7F8769DCC310 for item in report["candidates"]))

    def test_noncanonical_and_marker_checks_retained(self):
        for raw in ["000000000080", "41414141"]:
            with self.subTest(raw=raw):
                report = self.report("--bytes", raw, "--partial")
                self.assertEqual(report["candidates"][0]["disposition"], "reject")
                self.assertEqual(report["usable_count"], 0)
                self.assertEqual(report["candidates"][0]["completion_assumption"], "zero-extension")

    def test_human_output_discloses_assumption(self):
        result = self.tool("--bytes", LEAK.hex(), "--partial")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"observed=6/8 assumption=zero-extension", result.stdout)

    def test_invalid_hex_rejected(self):
        result = self.tool("--bytes", "xyz", "--partial")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"--bytes must contain hexadecimal bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()
