#!/usr/bin/env python3
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
CLAUDE = os.path.join(ROOT, "CLAUDE.md")
AGENTS = os.path.join(ROOT, "AGENTS.md")


class AgentEntrypointTests(unittest.TestCase):
    def setUp(self):
        with open(CLAUDE, encoding="utf-8") as f:
            self.text = f.read()

    def test_startup_context_stays_bounded(self):
        self.assertLessEqual(len(self.text.encode("utf-8")), 7000)

    def test_fast_path_is_the_default(self):
        # Guard the architecture, not one particular heading spelling.
        self.assertIn("FAST = route → query → test → verify", self.text)
        self.assertIn("rat route <artifact>", self.text)
        self.assertIn("rat snapshot --root . --budget-bytes 6000", self.text)
        self.assertIn("Do not preload doctrine", self.text)

    def test_deep_is_lazy_not_removed(self):
        self.assertIn("Escalate to DEEP only when needed", self.text)
        self.assertIn("doctrine/PRIMITIVE_GATE.md", self.text)
        self.assertIn("knowledge/GROUNDING_INDEX.md", self.text)
        self.assertNotIn("## 🚩 START HERE", self.text)
        self.assertNotIn("읽는 순서", self.text)

    def test_codex_entrypoint_tracks_claude_file(self):
        self.assertTrue(os.path.islink(AGENTS), "AGENTS.md must remain a symlink")
        self.assertEqual(os.readlink(AGENTS), "CLAUDE.md")


if __name__ == "__main__":
    unittest.main()
