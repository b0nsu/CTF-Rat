import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
ROOT = os.path.abspath(os.path.join(BIN, ".."))
sys.path.insert(0, BIN)

from ratlib.metrics import aggregate, iter_tool_results


class DecompInvocationTelemetryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
