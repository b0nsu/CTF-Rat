"""Deterministic, fail-closed learned Pattern Card retrieval tests."""
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.patterns import project_patterns


class LearnedPatternRetrieval(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        skill = os.path.join(self.root, "skills", "rev-checker", "SKILL.md")
        os.makedirs(os.path.dirname(skill))
        with open(skill, "w", encoding="utf-8") as file:
            file.write("## SIGNALS\nCompare\n## FIRST ACTION\nInspect\n## PIVOT\nRefute\n")
        self.learned = os.path.join(self.root, "knowledge", "learned")
        os.makedirs(os.path.join(self.learned, "rev"))
        os.makedirs(os.path.join(self.root, "artifacts"))
        self.proof = os.path.join(self.root, "artifacts", "reproduction.txt")
        with open(self.proof, "wb") as file:
            file.write(b"locally reproduced fixture\n")

    def lesson(self, status="validated", index_status=None, lead="checker", proof_digest=None):
        digest = proof_digest or "sha256:" + hashlib.sha256(open(self.proof, "rb").read()).hexdigest()
        source = (
            "# Checker experience\n\n"
            "- Status: `%s`\n- Domain: rev\n- Router lead: `%s`\n\n"
            "- Validated evidence: `%s` (artifacts/reproduction.txt)\n\n"
            "## Summary\nInspect the compare sink first.\n\n"
            "## General principle\nAn input transform may feed the checker.\n\n"
            "## Applicability\n- Prerequisites: confirmed compare call\n\n"
            "## Failure conditions and counterexamples\n- No compare sink\n\n"
            "## Evidence\n- Reproduced locally\n\n"
            "## Reuse history\n| Challenge | Result | Evidence | Date |\n|---|---|---|---|\n"
        ) % (status, lead, digest)
        path = os.path.join(self.learned, "rev", "checker-experience.md")
        with open(path, "w", encoding="utf-8") as file:
            file.write(source)
        index_status = index_status or status
        with open(os.path.join(self.learned, "INDEX.md"), "w", encoding="utf-8") as file:
            file.write("# Learned\n\n## Rev\n\n| Pattern | Status | Source | Evidence |\n"
                       "|---|---|---|---|\n"
                       "| [checker-experience](rev/checker-experience.md) | `%s` | fixture | proof |\n"
                       % index_status)

    def query(self, **kwargs):
        return project_patterns(["checker"], [{"kind": "checker-function"}],
                                root=self.root, max_cards=3, **kwargs)

    def test_validated_lesson_is_source_bound_and_never_direct_evidence(self):
        self.lesson()
        cards, diagnostics = self.query()
        self.assertFalse(diagnostics)
        self.assertEqual(len(cards), 2)
        learned = cards[1]
        self.assertEqual(learned["id"], "learned:rev/checker-experience")
        self.assertEqual(learned["selection"]["lead"], "checker")
        self.assertEqual(learned["lesson_status"], "validated")
        self.assertEqual(learned["kind"], "hypothesis-aid")
        self.assertFalse(learned["direct_evidence"])
        self.assertTrue(learned["source"]["digest"].startswith("sha256:"))
        self.assertTrue(learned["source"]["evidence_digest"].startswith("sha256:"))

    def test_candidates_and_undeclared_leads_do_not_auto_load(self):
        self.lesson(status="candidate")
        self.assertEqual([x["id"] for x in self.query()[0]], ["checker"])
        self.lesson(lead="vm")
        self.assertEqual([x["id"] for x in self.query()[0]], ["checker"])

    def test_stale_proof_and_index_mismatch_fail_closed(self):
        self.lesson(proof_digest="sha256:" + "0" * 64)
        cards, diagnostics = self.query()
        self.assertEqual(len(cards), 1)
        self.assertEqual(diagnostics[-1]["code"], "learned_source_invalid")
        self.lesson(status="reused", index_status="validated")
        cards, diagnostics = self.query()
        self.assertEqual(len(cards), 1)
        self.assertEqual(diagnostics[-1]["code"], "learned_source_invalid")

    def test_reused_card_requires_validation_binding(self):
        self.lesson(status="reused")
        self.assertEqual(self.query()[0][-1]["lesson_status"], "reused")
        lesson = os.path.join(self.learned, "rev", "checker-experience.md")
        with open(lesson, encoding="utf-8") as file:
            source = file.read()
        source = "\n".join(x for x in source.split("\n")
                           if not x.startswith("- Validated evidence: "))
        with open(lesson, "w", encoding="utf-8") as file:
            file.write(source)
        cards, diagnostics = self.query()
        self.assertEqual(len(cards), 1)
        self.assertEqual(diagnostics[-1]["code"], "learned_source_invalid")

    def test_budget_is_shared_with_static_cards(self):
        self.lesson()
        base, _ = project_patterns(["checker"], [], root=self.root, max_cards=1)
        size = len(json.dumps(base[0], ensure_ascii=False, sort_keys=True).encode("utf-8"))
        cards, diagnostics = self.query(budget_bytes=size + 1)
        self.assertEqual(len(cards), 1)
        self.assertEqual(diagnostics[-1]["code"], "budget_omitted")

    def test_symlinked_evidence_cannot_escape_repository(self):
        self.lesson()
        outside = tempfile.NamedTemporaryFile()
        self.addCleanup(outside.close)
        os.unlink(self.proof)
        os.symlink(outside.name, self.proof)
        cards, diagnostics = self.query()
        self.assertEqual(len(cards), 1)
        self.assertEqual(diagnostics[-1]["code"], "learned_source_invalid")


if __name__ == "__main__":
    unittest.main()
