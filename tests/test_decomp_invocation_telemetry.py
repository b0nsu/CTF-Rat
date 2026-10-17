import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
ROOT = os.path.abspath(os.path.join(BIN, ".."))
sys.path.insert(0, BIN)

from ratlib.metrics import aggregate, iter_tool_results, benchmark_envelope_observations
from ratlib.decomp_cache import write_meta, record_invocation


class DecompInvocationTelemetryTests(unittest.TestCase):
    def test_cli_ghidra_failure_is_recorded_with_exit_70(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as out:
                out.write(b"fixture-binary")
            ghidra = os.path.join(d, "ghidra")
            os.makedirs(os.path.join(ghidra, "support"))
            os.makedirs(os.path.join(ghidra, "Ghidra"))
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as out:
                out.write("application.version=fixture-1\n")
            analyze = os.path.join(ghidra, "support", "analyzeHeadless")
            with open(analyze, "w") as out:
                out.write("#!/bin/sh\nexit 11\n")
            os.chmod(analyze, 0o755)
            result = subprocess.run([os.path.join(BIN, "decomp"), binary, "main"],
                                    env=dict(os.environ, CTF_HOME=ROOT, GHIDRA_HOME=ghidra,
                                             XDG_CONFIG_HOME=os.path.join(d, "xdg")),
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 70, result.stderr)
            docs = list(iter_tool_results(os.path.join(d, ".rat")))
            self.assertEqual(len(docs), 1)
            self.assertEqual((docs[0]["status"], docs[0]["exit"]["code"]), ("error", 70))

    def test_failed_invocation_keeps_original_exit_and_is_not_an_analysis_success(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as out:
                out.write(b"fixture-binary")
            ghidra = os.path.join(d, "ghidra")
            os.makedirs(os.path.join(ghidra, "Ghidra"))
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as out:
                out.write("application.version=fixture-1\n")
            self.assertTrue(record_invocation(
                binary + ".decomp", binary, ghidra, os.path.join(BIN, "ghidra_scripts"),
                "miss", "error", "function", "foo", "2026-10-17T00:00:00+00:00",
                time.monotonic_ns(), 70, "call-failed"))
            docs = list(iter_tool_results(os.path.join(d, ".rat")))
            self.assertEqual(len(docs), 1)
            self.assertEqual((docs[0]["status"], docs[0]["exit"]["code"]), ("error", 70))
            self.assertEqual(aggregate(docs)["result_class_counts"], {"call-failed": 1})

    def test_bad_instruction_in_named_cached_function_is_partial(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as out:
                out.write(b"fixture-binary")
            ghidra = os.path.join(d, "ghidra")
            os.makedirs(os.path.join(ghidra, "Ghidra"))
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as out:
                out.write("application.version=fixture-1\n")
            cache = binary + ".decomp"
            os.makedirs(cache)
            with open(os.path.join(cache, "_index.txt"), "w") as out:
                out.write("00100000\tmain\t10\n")
            with open(os.path.join(cache, "main.c"), "w") as out:
                out.write("/* WARNING: Bad instruction */\nvoid main(void) { halt_baddata(); }\n")
            write_meta(cache, binary, ghidra, os.path.join(BIN, "ghidra_scripts"), "complete")
            fake_bin = os.path.join(d, "fake-bin")
            os.makedirs(fake_bin)
            timeout = os.path.join(fake_bin, "timeout")
            with open(timeout, "w") as out:
                out.write('#!/usr/bin/env bash\nshift 3\nexec "$@"\n')
            os.chmod(timeout, 0o755)
            result = subprocess.run(
                [os.path.join(BIN, "decomp"), "--format", "json", binary, "main"],
                env=dict(os.environ, CTF_HOME=ROOT, GHIDRA_HOME=ghidra,
                         XDG_CONFIG_HOME=os.path.join(d, "xdg"),
                         PATH=fake_bin + os.pathsep + os.environ.get("PATH", "")),
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "partial")
            self.assertIn("bad-instruction", result.stderr)
            self.assertIn("objdump -d --start-address", result.stderr)
            self.assertIn("0x400000", result.stderr)
            self.assertEqual(list(iter_tool_results(os.path.join(d, ".rat")))[0]["status"], "partial")

    def test_cli_miss_and_hit_are_persisted_as_tool_result_invocations(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as fh:
                fh.write(b"fixture-binary")

            ghidra = os.path.join(d, "ghidra")
            os.makedirs(os.path.join(ghidra, "support"), exist_ok=True)
            os.makedirs(os.path.join(ghidra, "Ghidra"), exist_ok=True)
            with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w", encoding="utf-8") as fh:
                fh.write("application.version=fixture-1\n")

            analyze = os.path.join(ghidra, "support", "analyzeHeadless")
            with open(analyze, "w", encoding="utf-8") as fh:
                fh.write(textwrap.dedent("""\
                    #!/usr/bin/env python3
                    import json, os, sys
                    args = sys.argv[1:]
                    i = args.index("DecompExport.java")
                    cache = args[i + 1]
                    os.makedirs(cache, exist_ok=True)
                    with open(os.path.join(cache, "_index.txt"), "w", encoding="utf-8") as out:
                        out.write("00100000\\tfoo\\t10\\n")
                    with open(os.path.join(cache, "foo.c"), "w", encoding="utf-8") as out:
                        out.write("int foo(void) { return 1; }\\n")
                    with open(os.path.join(cache, ".rat-decomp-status.json"), "w", encoding="utf-8") as out:
                        json.dump({"discovered": 1, "exported": 1, "failed": []}, out)
                """))
            os.chmod(analyze, 0o755)

            fake_bin = os.path.join(d, "fake-bin")
            os.makedirs(fake_bin)
            timeout = os.path.join(fake_bin, "timeout")
            with open(timeout, "w", encoding="utf-8") as fh:
                fh.write("#!/usr/bin/env bash\nshift 3\nexec \"$@\"\n")
            os.chmod(timeout, 0o755)

            env = os.environ.copy()
            env.update({
                "CTF_HOME": ROOT,
                "GHIDRA_HOME": ghidra,
                "PATH": fake_bin + os.pathsep + env.get("PATH", ""),
                "XDG_CONFIG_HOME": os.path.join(d, "xdg"),
            })
            cmd = [os.path.join(BIN, "decomp"), "--format", "json", binary, "foo"]
            first = subprocess.run(cmd, env=env, text=True, capture_output=True, check=False)
            second = subprocess.run(cmd, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(json.loads(first.stdout)["status"], "ok")
            self.assertEqual(json.loads(second.stdout)["status"], "ok")

            docs = list(iter_tool_results(os.path.join(d, ".rat")))
            self.assertEqual(len(docs), 2)
            self.assertEqual([doc["tool"]["name"] for doc in docs], ["decomp", "decomp"])
            self.assertEqual(sorted(doc["cache_state"] for doc in docs), ["hit", "miss"])
            self.assertEqual(len({doc["invocation_id"] for doc in docs}), 2)
            self.assertTrue(all(doc["parameters"]["operation"] == "function" for doc in docs))
            self.assertTrue(all(doc["parameters"]["requested"] == "foo" for doc in docs))

            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_requests"], 2)
            self.assertEqual(metrics["cache_hits"], 1)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["duplicate_tool_calls"], 0)
            scoped = benchmark_envelope_observations(os.path.join(d, ".rat"))
            self.assertEqual(scoped["by_tool"]["decomp"]["envelope_count"], 2)
            self.assertEqual(scoped["by_tool"]["decomp"]["cache_requests"], 2)
            self.assertEqual(scoped["by_tool"]["decomp"]["cache_hits"], 1)
            self.assertEqual(scoped["cache_requests"], 2)
            self.assertEqual(scoped["cache_hits"], 1)


if __name__ == "__main__":
    unittest.main()
