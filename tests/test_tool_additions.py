"""Regression for the T1/T2/T3 tool additions (plans/TOOL_ADDITIONS.md).

- rat brief card schema validation (T1)
- pwngadget parse/filter + cache hit/miss with a stubbed engine (T3)
- pwnlibc identify logic + readelf line parsing (T2)
"""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)


def _load(name, filename):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(BIN, filename))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run(*argv):
    return subprocess.run([sys.executable, *argv], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, cwd=ROOT, timeout=120)


class Selftests(unittest.TestCase):
    def test_pwngadget_selftest(self):
        p = _run(os.path.join(BIN, "pwngadget"), "selftest")
        self.assertEqual(p.returncode, 0, p.stdout.decode())

    def test_pwnlibc_selftest(self):
        p = _run(os.path.join(BIN, "pwnlibc"), "selftest")
        self.assertEqual(p.returncode, 0, p.stdout.decode())


class BriefCardSchema(unittest.TestCase):
    def test_valid_and_invalid(self):
        from ratlib.schema import validate, ValidationError
        card = {"schema": "rat.brief-card/v1", "binary": "x", "capabilities": {},
                "route": {}, "track_summary": {}, "libc": {}, "truncated": [], "side_effects": []}
        validate(card, "rat.brief-card/v1")
        del card["route"]
        with self.assertRaises(ValidationError):
            validate(card, "rat.brief-card/v1")


class BriefGeneration(unittest.TestCase):
    """Execution-level coverage for rat brief generation logic (T1 follow-up):
    hash-verified libc match, honest budget truncation, conflict rendering."""

    def setUp(self):
        self.rat = _load("rat", "rat")

    def _base_card(self, **over):
        card = {
            "schema": "rat.brief-card/v1", "binary": "t",
            "binary_sha256": "sha256:" + "0" * 64,
            "capabilities": {"angr": True},
            "route": {"track": "pwn", "subroute": "stack", "confidence": 0.9,
                      "signals": [], "next": []},
            "skill_path": "skills/pwn-stack/SKILL.md",
            "track_summary": {"protections": {"elf.nx": True}, "sinks": ["gets"]},
            "libc": {"supplied": None, "sha256": None, "reference_match": None, "match_method": None},
            "budget_tokens": None, "truncated": [], "side_effects": [],
        }
        card.update(over)
        return card

    # --- _libc_match: hash is the only trustworthy signal ---------------------
    def test_libc_match_hash_verified(self):
        with tempfile.TemporaryDirectory() as d:
            libc = os.path.join(d, "libc.so.6")
            with open(libc, "wb") as fh:
                fh.write(b"\x7fELFfake-libc-bytes")
            digest = self.rat._file_sha256(libc).split(":", 1)[1]
            db = os.path.join(d, "libc-db.json")
            with open(db, "w") as fh:
                json.dump({"entries": [{"version": "2.31-ubuntu", "sha256": digest}]}, fh)
            out = self.rat._libc_match(d, libc, db_path=db)
            self.assertEqual(out["reference_match"], "2.31-ubuntu")
            self.assertEqual(out["match_method"], "sha256")

    def test_libc_match_renamed_wrong_bytes_does_not_match(self):
        # A libc named like a known version but with different content must NOT match.
        with tempfile.TemporaryDirectory() as d:
            libc = os.path.join(d, "libc-2.31.so")
            with open(libc, "wb") as fh:
                fh.write(b"different-bytes-entirely")
            db = os.path.join(d, "libc-db.json")
            with open(db, "w") as fh:
                json.dump({"entries": [{"version": "2.31-ubuntu", "sha256": "a" * 64}]}, fh)
            out = self.rat._libc_match(d, libc, db_path=db)
            self.assertIsNone(out["reference_match"])
            self.assertIsNone(out["match_method"])
            self.assertIsNotNone(out["sha256"])  # digest still recorded

    def test_libc_match_no_db_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            libc = os.path.join(d, "libc.so.6")
            with open(libc, "wb") as fh:
                fh.write(b"bytes")
            out = self.rat._libc_match(d, libc, db_path=os.path.join(d, "nope.json"))
            self.assertIsNone(out["reference_match"])

    # --- render: verified vs unknown, conflict --------------------------------
    def test_render_verified_libc_line(self):
        card = self._base_card(libc={"supplied": "libc.so.6", "sha256": "sha256:" + "b" * 64,
                                      "reference_match": "2.35", "match_method": "sha256"})
        txt = self.rat._render_brief_text(card)
        self.assertIn("2.35 (sha256-verified)", txt)

    def test_render_unknown_libc_points_to_pwnlibc(self):
        card = self._base_card(libc={"supplied": "libc.so.6", "sha256": "sha256:" + "b" * 64,
                                      "reference_match": None, "match_method": None})
        txt = self.rat._render_brief_text(card)
        self.assertIn("unknown", txt)
        self.assertIn("pwnlibc", txt)

    def test_render_conflict_lists_alternatives(self):
        card = self._base_card()
        card["route"]["conflict"] = True
        card["route"]["alternatives"] = [{"track": "pwn", "subroute": "heap", "confidence": 0.6}]
        txt = self.rat._render_brief_text(card)
        self.assertIn("CONFLICT", txt)
        self.assertIn("heap", txt)

    # --- budget truncation: honest, re-checked --------------------------------
    def test_budget_large_no_truncation(self):
        card = self._base_card()
        self.rat._bound_brief_to_budget(card, 100000)
        self.assertEqual(card["truncated"], [])

    def test_budget_tiny_marks_over_budget(self):
        card = self._base_card()
        self.rat._bound_brief_to_budget(card, 1)  # 4 bytes -- core header alone exceeds
        self.assertIn("libc", card["truncated"])
        self.assertIn("track_summary", card["truncated"])
        self.assertIn("over-budget", card["truncated"])

    def test_budget_does_not_overtrim(self):
        # A budget that fits after trimming libc only must not also trim track_summary.
        card = self._base_card(libc={"supplied": "some/rather/long/path/to/libc.so.6",
                                     "sha256": "sha256:" + "c" * 64,
                                     "reference_match": "2.35-0ubuntu3", "match_method": "sha256"})
        full = len(self.rat._render_brief_text(card).encode())
        libc_only = dict(card, libc={"supplied": None, "sha256": None,
                                     "reference_match": None, "match_method": None,
                                     "note": "trimmed for budget"})
        trimmed_len = len(self.rat._render_brief_text(libc_only).encode())
        # pick a budget strictly between the trimmed and full size
        self.assertLess(trimmed_len, full)
        budget_tokens = (trimmed_len + full) // 2 // 4 + 1
        self.rat._bound_brief_to_budget(card, budget_tokens)
        self.assertEqual(card["truncated"], ["libc"])


class PwngadgetCache(unittest.TestCase):
    def test_cache_hit_after_miss(self):
        mod = _load("_pwngadget", "pwngadget")
        sample = "0x00401234 : pop rdi ; ret\n0x00401299 : ret\n"
        calls = {"n": 0}

        def fake_engine(binary, engine):
            calls["n"] += 1
            return sample, "ROPgadget", None

        mod._run_gadget_engine = fake_engine
        with tempfile.TemporaryDirectory() as d:
            binpath = os.path.join(d, "target")
            with open(binpath, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 64)
            os.environ["RAT_INDEX_ROOT"] = os.path.join(d, ".rat")
            try:
                rc1 = mod.query_binary(binpath, "pop rdi ; ret", "x86-64", 20, "json")
                rc2 = mod.query_binary(binpath, "pop rdi ; ret", "x86-64", 20, "json")
            finally:
                os.environ.pop("RAT_INDEX_ROOT", None)
            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)
            # engine invoked once; second call served from cache
            self.assertEqual(calls["n"], 1)

    def test_timeout_is_not_cached(self):
        """A timed-out engine must not poison the cache with a false-negative."""
        mod = _load("_pwngadget_to", "pwngadget")
        calls = {"n": 0}

        def timing_out(binary, engine):
            calls["n"] += 1
            return None, "ROPgadget", "timeout"

        mod._run_gadget_engine = timing_out
        with tempfile.TemporaryDirectory() as d:
            binpath = os.path.join(d, "target")
            with open(binpath, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 64)
            os.environ["RAT_INDEX_ROOT"] = os.path.join(d, ".rat")
            try:
                rc1 = mod.query_binary(binpath, "pop rdi ; ret", "x86-64", 20, "json")
                rc2 = mod.query_binary(binpath, "pop rdi ; ret", "x86-64", 20, "json")
            finally:
                os.environ.pop("RAT_INDEX_ROOT", None)
            self.assertEqual(rc1, mod.runner.EXIT_TIMEOUT)
            # not cached: the retry must re-run the engine, not serve a cached "(none)"
            self.assertEqual(rc2, mod.runner.EXIT_TIMEOUT)
            self.assertEqual(calls["n"], 2)

    def test_truncated_output_is_not_cached(self):
        """A truncated (incomplete) dump is emitted but never cached."""
        mod = _load("_pwngadget_tr", "pwngadget")
        calls = {"n": 0}

        def truncating(binary, engine):
            calls["n"] += 1
            return "0x00401234 : pop rdi ; ret\n", "ROPgadget", "truncated"

        mod._run_gadget_engine = truncating
        with tempfile.TemporaryDirectory() as d:
            binpath = os.path.join(d, "target")
            with open(binpath, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 64)
            os.environ["RAT_INDEX_ROOT"] = os.path.join(d, ".rat")
            try:
                rc1 = mod.query_binary(binpath, "pop rdi ; ret", "x86-64", 20, "json")
                rc2 = mod.query_binary(binpath, "pop rdi ; ret", "x86-64", 20, "json")
            finally:
                os.environ.pop("RAT_INDEX_ROOT", None)
            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)
            # truncated results are not cached; engine re-runs on the second call
            self.assertEqual(calls["n"], 2)


class PwnlibcParsing(unittest.TestCase):
    def test_readelf_line_regex(self):
        mod = _load("_pwnlibc", "pwnlibc")
        line = "   242: 0000000000050d70   45 FUNC    GLOBAL DEFAULT   15 system@@GLIBC_2.2.5"
        m = mod._SYM_LINE.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1), 16), 0x50d70)
        self.assertEqual(m.group(2).split("@")[0], "system")

    def test_identify_unknown_is_honest(self):
        mod = _load("_pwnlibc2", "pwnlibc")
        db = {"entries": [{"version": "2.27", "sha256": "a" * 64, "symbols": {"system": 0x4f550}}]}
        # a leak whose page offset matches nothing -> no candidates (unknown, not a guess)
        self.assertEqual(mod.identify(db, {"system": 0x7f0000000000 + 0x123}), [])


if __name__ == "__main__":
    unittest.main()
