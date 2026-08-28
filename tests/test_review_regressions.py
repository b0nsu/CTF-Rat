import os, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.contracts import execute
from ratlib.metrics import aggregate, iter_tool_results
from ratlib.state_v2 import _file_digest, trusted_producer_for_build


class DirectEvidenceBindingRegression(unittest.TestCase):
    def test_direct_subject_must_match_gdbq_execution_target(self):
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        gdbq = os.path.join(repo, "bin", "gdbq")
        with tempfile.TemporaryDirectory() as d:
            subject_a = os.path.join(d, "a.bin")
            subject_b = os.path.join(d, "b.bin")
            with open(subject_a, "wb") as f:
                f.write(b"subject-a")
            with open(subject_b, "wb") as f:
                f.write(b"subject-b")
            with self.assertRaisesRegex(ValueError, "direct_subject does not match verifier target"):
                execute(
                    [gdbq, subject_b, "quit"],
                    root=os.path.join(d, ".rat"),
                    input_paths=[subject_a, subject_b],
                    direct_subject=subject_a,
                )

    def test_symsolve_path_shim_has_trusted_producer_identity(self):
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        shim = os.path.join(repo, "bin", "symsolve")
        self.assertEqual(trusted_producer_for_build(_file_digest(shim)), "symsolve")


class PersistentTelemetryRegression(unittest.TestCase):
    def test_warm_cache_hit_survives_metrics_rescan(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, ".rat")
            first = execute(["/bin/echo", "persistent telemetry"], root=root, timeout=5)
            second = execute(["/bin/echo", "persistent telemetry"], root=root, timeout=5)
            self.assertEqual(first["cache_state"], "miss")
            self.assertEqual(second["cache_state"], "hit")

            docs = list(iter_tool_results(root))
            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_requests"], 2)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["cache_hits"], 1)
            self.assertAlmostEqual(metrics["cache_hit_ratio"], 0.5)

    def test_persisted_hit_record_is_not_a_fresh_evidence_envelope(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, ".rat")
            execute(["/bin/echo", "cached"], root=root, timeout=5)
            execute(["/bin/echo", "cached"], root=root, timeout=5)
            hit_docs = [doc for doc in iter_tool_results(root) if doc.get("cache_state") == "hit"]
            self.assertEqual(len(hit_docs), 1)
            extensions = hit_docs[0].get("extensions") or {}
            self.assertNotIn("evidence_policy", extensions)
            self.assertNotIn("envelope_digest", extensions)


if __name__ == "__main__":
    unittest.main()
