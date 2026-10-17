"""Bounded, read-only glibc 2.35 snapshot contract: no live target required."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib import gdb_session


class FakeMemoryMI:
    def __init__(self, memory, *, truncate=False):
        self.memory = memory
        self.calls = []
        self.truncate = truncate

    def command(self, command, timeout):
        self.calls.append((command, timeout))
        match = re.fullmatch(r"-data-read-memory-bytes (0x[0-9a-f]+) (\d+)", command)
        if not match:
            raise AssertionError(command)
        address, length = int(match[1], 16), int(match[2])
        data = bytes(self.memory.get(address + offset, 0) for offset in range(length))
        if self.truncate:
            data = data[:-1]
        return {"status": "ok", "mi_result": 'done,memory=[{contents="%s"}]' % data.hex()}


def store(memory, address, value, size=8):
    for offset, byte in enumerate(int(value).to_bytes(size, "little")):
        memory[address + offset] = byte


class HeapSnapshotTests(unittest.TestCase):
    def test_version_gated_snapshot_decodes_selected_regions(self):
        tcache, arena, chunk = 0x500000, 0x600000, 0x700000
        mem = {}
        store(mem, tcache + 2 * 2, 1, 2)
        store(mem, tcache + 128 + 2 * 8, 0x501000)
        for i, value in enumerate((0x800000, 0x810000, 0x820000, 0x830000)):
            store(mem, arena + 0x60 + i * 8, value)
        store(mem, chunk, 0x20)
        store(mem, chunk + 8, 0x41)
        target = 0x900000
        store(mem, chunk + 16, target ^ ((chunk + 16) >> 12))
        mi = FakeMemoryMI(mem)
        result = gdb_session._heap_snapshot(mi, {
            "layout": "glibc-2.35-x86_64",
            "tcache": hex(tcache), "arena": hex(arena), "chunk": hex(chunk)}, 5)
        self.assertEqual(result["status"], "ok")
        snap = result["snapshot"]
        self.assertFalse(snap["direct_evidence"])
        self.assertEqual(snap["regions"]["tcache"]["bins"],
                         [{"index": 2, "count": 1, "head": "0x501000"}])
        self.assertEqual(snap["regions"]["arena"]["unsorted_fd"], "0x820000")
        self.assertEqual(snap["regions"]["arena"]["top"], "0x800000")
        self.assertEqual(snap["regions"]["chunk"]["candidate_decoded_fd"], hex(target))
        self.assertLessEqual(len(mi.calls), 5)
        self.assertTrue(all(int(cmd.split()[-1]) <= 256 for cmd, _ in mi.calls))

    def test_incomplete_region_is_partial_not_fake_zero_fact(self):
        mi = FakeMemoryMI({}, truncate=True)
        report = gdb_session._heap_snapshot(mi, {"layout": "glibc-2.35-x86_64",
                                                 "tcache": "0x500000"}, 5)
        self.assertEqual(report["status"], "partial")
        self.assertNotIn("tcache", report["snapshot"]["regions"])
        self.assertEqual(report["snapshot"]["unresolved"][0]["region"], "tcache")

    def test_mi_read_timeout_terminates_snapshot_as_timeout(self):
        class TimedOutMI:
            calls = 0

            def command(self, command, timeout):
                self.calls += 1
                return {"status": "timeout", "mi_result": None}

        mi = TimedOutMI()
        report = gdb_session._heap_snapshot(mi, {"layout": "glibc-2.35-x86_64",
                                                 "tcache": "0x500000", "chunk": "0x700000"}, 5)
        self.assertEqual(report["status"], "timeout")
        self.assertEqual(mi.calls, 1)
        self.assertEqual(report["snapshot"]["unresolved"],
                         [{"region": "tcache", "reason": "memory read timed out"}])
        self.assertNotIn("chunk", report["snapshot"]["regions"])

    def test_unsupported_layout_and_foreign_or_unaligned_addresses_rejected(self):
        for params in (
            {"layout": "glibc-2.39-x86_64", "tcache": "0x500000"},
            {"layout": "glibc-2.35-x86_64"},
            {"layout": "glibc-2.35-x86_64", "tcache": "0x500001"},
            {"layout": "glibc-2.35-x86_64", "chunk": "0x0"},
            {"layout": "glibc-2.35-x86_64", "arena": "main_arena"},
            {"layout": "glibc-2.35-x86_64", "arena": "0x1000; shell"},
        ):
            with self.subTest(params=params), self.assertRaises(ValueError):
                gdb_session._heap_snapshot(FakeMemoryMI({}), params, 5)


if __name__ == "__main__":
    unittest.main()
