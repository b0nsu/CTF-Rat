import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOLVING = ROOT / "doctrine" / "SOLVING.md"
README = ROOT / "README.md"


class DeepWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SOLVING.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")

    def test_deep_is_evidence_handoff_not_fixed_restart_loop(self):
        self.assertIn("## DEEP 진입 계약", self.text)
        self.assertNotIn("## 고정 루프", self.text)
        self.assertNotIn("제공된 artifact에 `newchal <name> <bin> [libc]`를 실행하고 `recon`(pwn) 또는 `revq`(rev)로 triage한다.", self.text)
        self.assertIn("`newchal`, `recon`, 전체 `revq`, 전체 decompile을 DEEP 진입 의식처럼 다시 실행하지 않는다.", self.text)
        self.assertIn("`rat state compact --budget-tokens N`", self.text)

    def test_deep_loop_is_bounded_and_discriminating(self):
        self.assertIn("bounded competing branches (<=3)", self.text)
        self.assertIn("one discriminating experiment", self.text)
        self.assertIn("가장 저비용이며 branch를 가장 많이 줄이는 실험 하나", self.text)
        self.assertIn("branch가 하나면 fan-out하지 않는다", self.text)

    def test_readme_deep_flow_resumes_current_evidence(self):
        self.assertIn("H -->|next discriminator| D", self.readme)
        self.assertNotIn("H --> B", self.readme)
        self.assertIn("FAST evidence handoff + bounded convergence loop", self.readme)
    def test_deep_keeps_deterministic_verification_authoritative(self):
        self.assertIn("primitive proof", self.text)
        self.assertIn("deterministic verification", self.text)
        self.assertIn("deterministic verifier가 명확한 경우 skeptic은 기본 OFF", self.text)
        self.assertIn("PRIMITIVE_GATE.md", self.text)


if __name__ == "__main__":
    unittest.main()
