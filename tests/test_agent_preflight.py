"""Startup should warn about optional analyzers without blocking the agent."""
import importlib.machinery
import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("agent_preflight_test", str(ROOT / "bin" / "agent-preflight"))
spec = importlib.util.spec_from_loader(loader.name, loader)
preflight = importlib.util.module_from_spec(spec)
loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def _run_without_analysis_stacks(self, strict):
        env = {key: value for key, value in os.environ.items() if key != "RAT_PREFLIGHT_STRICT"}
        if strict:
            env["RAT_PREFLIGHT_STRICT"] = "1"
        with patch.dict(os.environ, env, clear=True), \
             patch.object(preflight, "check", side_effect=lambda label, *_args, **_kw: not (
                 label.startswith("pwntools") or label.startswith("angr"))), \
             patch.object(preflight, "ghidra_command", return_value=(["ghidra"], None)):
            return preflight.main()

    def test_missing_pwn_and_angr_still_launches_agent(self):
        self.assertEqual(self._run_without_analysis_stacks(strict=False), 0)

    def test_strict_opt_in_blocks_missing_analysis_stacks(self):
        self.assertEqual(self._run_without_analysis_stacks(strict=True), 2)


if __name__ == "__main__":
    unittest.main()
