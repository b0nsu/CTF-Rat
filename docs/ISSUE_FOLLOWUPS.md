# Issue follow-ups (2026-10-13–14)

Code inspected against GitHub `main` at
`517964d3c379c53754123ea6da2d87714342ee4e`. The fixes in this working tree
address the operational reports; they are not model solve-rate measurements.

## Heap/runtime follow-ups (#104–#107; 2026-10-16)

These are bounded regression and diagnostic changes, **not** a claim that the
reporter's original DreamHack challenge was replayed or fixed.

- **#104:** `pwn-heap` PIVOT and the existing `rat query pattern` path now
  describe the *conditional* unsorted-bin split/refill mismatch. Static heap
  imports do **not** imply this failure; confirm allocation provenance in
  the live, libc-matched state before changing an exploit plan.
- **#105:** `rat dyn session heap` reads an operator-selected, owned stopped
  inferior. It supports only the pinned `glibc-2.35-x86_64` layout, at most
  1024 bytes per snapshot and up to 256 bytes per GDB/MI request.
  Incomplete reads remain `partial` and only candidate artifacts are captured.
  The session does **not** yet support interactive stdin or arbitrary-PID attach.
- **#106:** `rat-dyn --stderr-mode pipe|devnull|stdout` exposes three
  explicitly named child stderr topologies through the existing subprocess
  runner. Default remains `pipe` (separate stdout/stderr PIPE). `stdout`
  merges into the bounded stdout capture; `devnull` drops child stderr.
  Neither mode is the same as pwntools' default stdout PTY.
  Nondefault modes get distinct execution environment digests; a diagnostic
  trace with suppressed/merged stderr cannot establish default-PIPE
  verification equivalence. The reporter's 0/3 versus 3/3 SIGSEGV mechanism
  remains **UNVERIFIED**: compare fixed binary/libc/input, stdout/stderr
  topology, launch flags, crash site and allocator snapshots in a matrix.
- **#107:** the existing `pwn-heap` Pattern Card describes a conditional
  `sequential_round_trips * measured_RTT` latency floor. It encourages
  reducing required operations and only pipelines when protocol semantics
  permit it; no unsupported remote batching helper was added.

Focused regression commands (run on a machine with repository dependencies):

```sh
python3 -m unittest tests.test_heap_snapshot_v21 tests.test_runner_stdio_topology \
  tests.test_gdb_session_v21 tests.test_patterns_v21
```

## Operational reports

- [#82](https://github.com/b0nsu/CTF-Rat/issues/82): permit a provisional route
  with no recommended decision when independent probes compete. Regression
  tests now validate those generated documents. Cached named functions with
  Ghidra bad-instruction output return `partial` plus bounded disassembly
  guidance. `recon` retains import/protection facts and inspection priorities,
  with empty technique predictions and low confidence; it no longer predicts
  FSOP, tcache, ret2win or ROP from imports alone.
- [#83](https://github.com/b0nsu/CTF-Rat/issues/83): bounded Nim/Go/Rust runtime
  symbol markers contextualize a sole `memcpy` signal. The copy callsite stays
  available for inspection without asserting a stack destination. Binary-wide
  input/rejection strings can suggest an existing application entry function;
  the signal remains heuristic with binary scope, not a proven function xref,
  length check, constant table or oracle. Strong input sinks and independent
  heap/format leads remain available. Tests use synthetic router inputs; the
  reporter's challenge binary was not attached, so its exact output is not
  claimed as reproduced.
- [#84](https://github.com/b0nsu/CTF-Rat/issues/84): document direct/Bash
  invocation of `decomp` and add `mod2solve` for bounded equations modulo
  powers of two. Its valuation-aware elimination supports even pivots,
  rectangular and singular systems, and checks the returned solution against
  the original equation. Mathematical verification does not establish a
  verified challenge solve or record a primitive PASS.

## Partial pointer leaks (#87)

- [#87](https://github.com/b0nsu/CTF-Rat/issues/87): `pwnleak --partial`
  accepts one 1–8 byte packed x86-64 little-endian pointer through `--bytes`
  or raw file/stdin input. Partial candidates report the observed and missing
  byte counts and the explicit zero-extension assumption. Text input,
  unsupported profiles and multiple-pointer partial input are rejected.
  Full-width and default multi-pointer behavior stay compatible. Pointer
  classifications remain candidates, not evidence of a stable leak primitive.

## Kernel workflow reports (#88–#92)

- [#88](https://github.com/b0nsu/CTF-Rat/issues/88) and
  [#92](https://github.com/b0nsu/CTF-Rat/issues/92): a dependency-free bounded
  header probe recognizes Linux boot protocol signatures. `newchal` skips
  generic ELF recon/pwninit and generates a kernel harness placeholder;
  `rat route` retains a kernel lead and explicit ELF-extraction prerequisite
  without attempting an unsupported loader. Linux `scripts/extract-vmlinux`
  is guidance, not a bundled or automatically executed extraction tool.
- [#89](https://github.com/b0nsu/CTF-Rat/issues/89): corroborating ELF sections
  and core symbols identify `vmlinux`. Single-text recovered ELFs require
  several core symbols plus kernel-space executable VMAs. Defined executable
  NOTYPE symbols are retained, including their actual ELF addresses. Kernel
  `rat query func` also retains the selected function's address in its facts.
  `revq` uses bounded symbol metadata rather than whole-kernel CFG recovery;
  calls/xrefs and string coverage are unavailable and `analysis_complete`
  remains false. Incidental global VM/crypto substrings do not select REV
  probes on identified kernels; independent callsite/import facts remain.
  Static identity does not commit `pwn-kernel` or mint primitive evidence.
- [#90](https://github.com/b0nsu/CTF-Rat/issues/90): kernel or >=16 MiB Ghidra
  imports fail before analysis unless `--allow-full-analysis` is given. The
  diagnostic exposes whole-program import/export cost and the `--timeout`
  budget. Cached functions are served normally; a missing address that would
  trigger a fresh one-shot import is subject to the same guard. Refresh/stale
  caches are preserved when that import is declined. This exposes the cost;
  it does not implement a function-only Ghidra import.
- [#91](https://github.com/b0nsu/CTF-Rat/issues/91): `rat-adapt --root` is
  documented as an artifact-store path. A challenge root containing `.rat`
  is rejected before running a tool, with the corrected `.rat` path. Existing
  explicit store paths and default `./.rat` semantics remain supported.

Regression fixtures exercise real CLI dispatch, header false positives,
32/64-bit and both-endian ELF symbol tables, recovered NOTYPE addresses,
single-text recovery, bounded malformed metadata, replacement of a legacy
empty kernel cache, import opt-in, ingestion and STATE artifact resolution.
The reporter's original image hashes are unavailable locally; these are
synthetic format/contract reproductions, not runs of the Copy Fail challenge.

Validation for this follow-up: all nine required tool selftests and all 15
writeup-pipeline tests passed. The 101-test related set passed on macOS
(two environment skips) and x86 Linux (one optional angr-in-parent skip).
All 13 new kernel/store regressions passed on Linux, including a real
`gdbq info files` direct-envelope → STATE roundtrip. The real REV E2E passed
with native Unicorn, concrete verification and STATE engine provenance.
The native-angr Linux dispatcher/callsite run passed all 31 tests without skips,
covering the engine-dependent cases skipped by the separate pwn interpreter.

## Existing retrieval versus #69 acceptance

[#69](https://github.com/b0nsu/CTF-Rat/issues/69) overlaps implemented behavior
in `bin/ratlib/patterns.py`, `bin/rat::cmd_query_pattern`, and
`tests/test_patterns_v21.py`: up to three deterministic cards, exact skill
sections, source digests, candidate labeling, missing/stale source diagnostics,
byte limits, and no skill/primitive commitment from retrieval.

This is not evidence that every acceptance condition is complete:

- Knowledge references come from the fixed `KNOWLEDGE` map in `patterns.py`,
  not a projection of `knowledge/GROUNDING_INDEX.md`.
- Unrecognized leads are filtered from the catalog. They are not distinguished
  from a genuinely empty input by a fail-closed diagnostic.
- Budget/source failures produce bounded diagnostics, often partial results;
  the issue's intended all-or-nothing semantics need reconciliation with the
  existing query contract.
- The real agent A0/A1 held-out comparison has no posted results. Synthetic
  tests and CI do not establish faster or more frequent verified solves.

Leave #69 open pending scope reconciliation and measured acceptance. This fix
does not extend experimental retrieval or create a new benchmark/cache/gate.

## #81 independent model experiment

[#81](https://github.com/b0nsu/CTF-Rat/issues/81) specifies an immutable A0 main
baseline, PR #79 A1 and PR #80 A1b, with at least three attempts per challenge
and comparable model/tool/environment provenance. PR #79 explicitly reports
the model comparison as not run. The `main` tree has neither `bin/ratbench`
nor `bench/suite.json`; `dev` tooling must not silently become the main baseline.

Run this separately in answer-free workspaces from the specified immutable
revisions, using an independently reviewed runner and eligible model CLI.
The modified working tree is not the unmodified A0 revision. Unit/selftests
and the real crackme concrete-verification regression remain correctness
evidence only, not model-level ablation results.

## Validation

- All nine required tool selftests passed. `tests.test_writeup_pipeline`
  passed all 15 tests.
- The 36 focused route/recon/decomp/algebra/schema/skill-assessment tests
  passed on the host and the x86 Linux container. Algebra coverage includes
  every 2-by-2 matrix and target modulo four (4,096 systems), comparison with
  brute-force solution sets, and a deterministic 67-by-67 mod-256 system.
- The expanded 69-test set, including cache integrity/resealing, pattern
  retrieval, PWN queries and writeup gates, passed on native ARM Linux.
- `bash tests/e2e_rev.sh --require-engine` passed with native Unicorn: real
  crackme input recovery, concrete verification, STATE provenance, router and
  doctor dispatch, and the VM regression.
- The x86 container's full suite ran 616 tests: 3 failures, 5 errors, 11 skips.
  GDB cannot read the emulated target's CS register. A standalone compiled
  `int main(void) { return 0; }` under plain GDB reproduces the same error
  without any CTF-Rat tool.
- Native ARM Linux full suite: 616 tests, 602 passed, 13 skipped, 1 failure.
  The existing `test_pwncrash_reproduces_local_core_evidence` fixture exits
  normally on ARM, so it produces no crash/core. Running that test from an
  isolated `git archive HEAD` of the unchanged baseline reproduces the same
  failure. No test was disabled or weakened to produce a green summary.

The full suite is therefore not claimed ALL GREEN on these container
platforms; the operational changes and required selftests pass, while the
existing platform-dependent integration limitations remain recorded.
