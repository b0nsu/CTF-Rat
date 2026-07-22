# P4 architecture runner: release-input blocker

## Finding

The checked-in `benchmarks/corpus/v1` cannot produce an architecture benchmark.
All 40 entries are synthetic known-answer fixtures, rather than CTF tasks that
an architecture must analyse and solve.  For example,
`rev-native-01/src/fixture.py` accepts only `solve:rev-native-01`, while its
checker accepts only `verified:rev-native-01`.  The same pattern is present in
every `src/fixture.py` entry.

The manifests also use placeholder artifact digests and do not supply an
executable binary artifact.  This means there is neither a reproducible target
for P2/P3 tools nor a meaningful solver input.  The existing `--runner`
interface is only an external-command adapter; it does not include a model
agent, prompt executor, or an implementation which drives `rat-*` tools.

Consequently, emitting A0--A5 results from this corpus would measure prior
knowledge of the fixture token, not CTF-solving performance.  `rat-bench run
--runner` now refuses this corpus.  `--fixture-smoke` remains limited to
collector/oracle plumbing tests and is never release evidence.

## Required input to unblock real measurements

Provide a versioned, local-only corpus root with 40 release-eligible challenge
directories.  Each directory must contain:

1. A legal source tree and deterministic local build recipe, or a licensed
   binary plus a fetch script and pinned upstream digest.
2. A built executable (`artifacts.binary`) plus correct source, binary, and
   environment/libc/loader digests.
3. A deterministic scenario that does not expose the winning input to the
   solver, and a local checker isolated from the solver process.
4. Evaluator-only ground truth for fact/finding/primitive-or-solution claims,
   with the category/difficulty/split distribution required by P4.
5. An architecture executor command or model-agent integration that invokes
   the configured A0--A5 component sets and emits the documented runner JSON
   (candidate stdout, claim IDs, and measured token/cache/tool metrics).

Once those assets exist, the minimum execution is one `rat-bench run --runner
...` per release-plan entry (23 total), followed by a per-run `collect`; A0
metrics are supplied as the reference for every relative PDF target.  The
runner's output is still independently checked by the local oracle.
