"""Deterministic function-start discovery for stripped ELFs (revq --fast).

Verifies the prologue/call-target sweep that supplies start-address candidates
for `revq --func` on stripped binaries, where nm/readelf yield no functions.
"""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "bin"

SOURCE = r"""
#include <stdio.h>
__attribute__((noinline)) int helper_a(int x){return x*3+1;}
__attribute__((noinline)) int helper_b(int x){return helper_a(x)-7;}
__attribute__((noinline)) int helper_c(int x){return helper_b(x)*2;}
__attribute__((noinline)) int helper_d(int x){return helper_c(x)+helper_a(x);}
int main(void){printf("%d\n", helper_d(5)); return 0;}
"""


def revq_module():
    sys.path.insert(0, str(BIN))
    loader = importlib.machinery.SourceFileLoader("_test_discovery_revq", str(BIN / "revq"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@unittest.skipUnless(sys.platform == "linux"
                     and all(shutil.which(t) for t in ("gcc", "nm", "readelf", "strip")),
                     "Linux gcc/binutils required")
class FunctionDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.src = root / "fd.c"
        cls.src.write_text(SOURCE)
        cls.sym = root / "fd_sym"
        cls.stripped = root / "fd_stripped"
        subprocess.run(["gcc", "-O0", "-o", str(cls.sym), str(cls.src)],
                       check=True, capture_output=True, timeout=30)
        shutil.copy(cls.sym, cls.stripped)
        subprocess.run(["strip", str(cls.stripped)], check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _candidates(self, binary):
        out = subprocess.run([str(BIN / "revq"), str(binary), "--fast", "--refresh",
                              "--format", "json"], capture_output=True, text=True,
                             timeout=30, check=True)
        return json.loads(out.stdout)

    def _text_symbol_functions(self, binary, load_base=0):
        # nm reports file VMAs; candidates are in loader space (angr rebases a PIE
        # to 0x400000), so shift the ground truth by the same base to compare.
        gt = set()
        nm = subprocess.check_output(["nm", "-C", "--defined-only", str(binary)], text=True)
        for line in nm.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[1] in ("t", "T"):
                try:
                    gt.add(int(parts[0], 16) + load_base)
                except ValueError:
                    pass
        return gt

    def test_stripped_binary_yields_candidates(self):
        doc = self._candidates(self.stripped)
        self.assertEqual(len(doc["functions"]), 0, "stripped nm must yield no functions")
        self.assertGreater(doc["counts"]["function_candidates_total"], 0,
                           "stripped binary must produce start-address candidates")
        sources = {c["source"] for c in doc["function_candidates"]}
        # Modern gcc emits endbr64 at function entry; that must be a source.
        self.assertIn("endbr64", sources)
        # An info diagnostic must point the user at revq --func.
        self.assertTrue(any("--func" in (d.get("message", "") if isinstance(d, dict) else str(d))
                            for d in doc.get("analysis_diagnostics", [])))

    def test_candidates_recover_real_function_starts_with_high_precision(self):
        doc = self._candidates(self.stripped)
        # Candidates are loader-space; the control was built -no-pie? default gcc
        # here is PIE (rebased to 0x400000).  Match the ground-truth space to the
        # candidates' by reading the sweep's own base decision from pie.
        load_base = 0x400000 if doc.get("pie") else 0
        gt = self._text_symbol_functions(self.sym, load_base=load_base)
        self.assertGreaterEqual(len(gt), 5, "expected several .text symbols in the control")
        cand = {c["addr"] for c in doc["function_candidates"]}
        hit = gt & cand
        # The user functions (helper_*/main) begin with endbr64+prologue and must
        # be recovered; recall over ALL .text symbols includes _init/_fini stubs
        # that have no standard prologue, so require a solid majority, not 100%.
        self.assertGreaterEqual(len(hit) / len(gt), 0.6,
                                "recall %d/%d too low" % (len(hit), len(gt)))
        # Precision: candidates that fall on a real .text symbol start.  The
        # endbr64-shadow dedup must keep this high (no "+4 byte" duplicates).
        self.assertGreaterEqual(len(hit) / len(cand), 0.8,
                                "precision %d/%d too low (dup prologues?)" % (len(hit), len(cand)))

    def test_endbr64_shadow_dedup_no_plus_four_duplicates(self):
        # Regression for the dedup: a function starting with endbr64 (4 bytes) is
        # followed by push rbp; that push must NOT appear as its own candidate.
        cand = sorted(c["addr"] for c in self._candidates(self.stripped)["function_candidates"])
        for i, addr in enumerate(cand):
            self.assertNotIn(addr + 4, cand[i + 1:i + 2],
                             "addr %#x and %#x look like endbr64 + its own prologue" % (addr, addr + 4))

    def test_not_an_x86_elf_returns_no_candidates(self):
        revq = revq_module()
        # Non-x86 arch is unsupported by the sweep and must return [] cleanly.
        self.assertEqual(revq._discover_function_candidates(str(self.stripped), "aarch64"), [])


if __name__ == "__main__":
    unittest.main()
