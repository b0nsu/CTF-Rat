# PDF traceability and post-merge backlog

This document is the implementation index for the three Korean PDF reports:

- `CTF-Rat_bin_architecture_upgrade_report_ko_corrected.pdf` — original P0–P4 roadmap.
- `CTF-Rat_ssttff_branch_code_review_ko.pdf` — first implementation review.
- `CTF-Rat_ssttff_second_review_ko.pdf` — second implementation review.

The authoritative implementation branch is `main`. The historical `ssttff`
branch remains an archive of the original implementation series and challenge
solve artifacts; it is not the promotion source.

## Completed in main

| Requirement | Evidence |
| --- | --- |
| P0 safe archive, bounded runner, run manifest | `ratlib.safe_archive`, `ratlib.runner`, `ratlib.run_manifest` and stability tests |
| P1 artifact store and typed lifecycle | `ratlib.artifact`, `ratlib.state_v2`, schema and P1 contract tests |
| Empty verification and ROP-gate bypass closure | `rat-verify` strict conditions; `rat-rop --index-only` split |
| Verification promotion gate | immutable `rat.verification-report/v1` artifact required by orchestration |
| P3 task cap, phase attempts, rollback lineage | orchestration transaction lock, lineage fields and multiprocess regression |
| Broker input binding and fail-closed execution | artifact bindings plus Bubblewrap-required policy |
| P2 truthfulness | experimental metadata, VM strict oracle, bounded fuzz reproduction |
| CI baseline | `p0-p4-regression` workflow plus benchmark smoke |

## Follow-up status (uncommitted review branch)

The following closeout changes are implemented on `followup/pdf-review-closeout`
and verified locally; they are deliberately separate from the already-merged
integration until reviewed.

| Requirement | Status | Evidence |
| --- | --- | --- |
| Interrupted v1 migration must resume without duplicate events | implemented | deterministic `legacy_source_id`, resume regression |
| v2 must be the default state view after migration | implemented | `state show` v2-preferred, `--legacy` escape hatch |
| Non-ELF must not claim ELF protections | implemented | PE-like fixture regression |
| Function-level decomp failure must be visible | implemented | export status metadata forces `partial` |
| ctfpull/newchal must acquire the active lock as one hand-off | implemented | guard transaction before scaffold |

## Remaining long-term work

| Priority | Requirement from reports | Acceptance test |
| --- | --- | --- |
| P3 | Artifact producer trust policy must not be self-asserted | untrusted artifact cannot obtain direct quality |
| P3 | Sandbox availability must be an explicit deployment requirement | unavailable backend remains fail-closed |
| P4 | Benchmark must use a private, representative corpus before performance claims | corpus manifest, baseline and holdout report |
| Ops | Keep solve binaries, libc, flags and generated decompile output outside architecture PRs | repository hygiene CI check |

## Promotion rule

P2 tools remain experimental until their output is backed by a verified
artifact and the relevant P1/P3 gate accepts it. Benchmark smoke validates
plumbing only; it does not establish solve-rate or production readiness.
