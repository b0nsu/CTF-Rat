---
name: ctf-writeup
description: Generates a local, evidence-backed CTF analysis handoff. Submission output requires explicit operator confirmation.
license: MIT
compatibility: Requires a filesystem-based agent with local shell and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep
metadata:
  user-invocable: "true"
  argument-hint: "[challenge-name]"
---

# CTF Local Analysis Write-up Generator

Generate an honest local analysis record from `STATE.jsonl` and the supplied artifacts.
The canonical field contract is `doctrine/WRITEUP_FORMAT.md`.

## Scope

- Default to `HANDOFF.md`.
- Stop the automated path at a locally reproduced primitive PASS.
- Do not infer solve status from words such as `flag`, `shell`, or `SOLVED` in notes.
- Do not search for challenge answers or existing writeups.
- Do not claim exploit chaining, flag acquisition, submission, or remote success without explicit
  operator confirmation and matching local evidence.
- Generate completed documents only with a structured operator attestation whose evidence digest
  is present in the current artifact or authoritative v2 observation set.
- Treat legacy PASS text as a candidate. Materialized STATE v2, including invalidation and stale
  transitions, is authoritative whenever it exists.
- Refuse to overwrite an existing generated document unless regeneration is explicitly requested.

## Workflow

1. Read the materialized STATE v2 view when present; otherwise render legacy state without trusting
   legacy PASS promotion.
2. Record supplied artifact, libc, loader, input, and environment digests.
3. Link every primitive PASS to its minimal input, command, observed registers or marker, and
   evidence files. Downgrade unsupported PASS language instead of filling gaps by inference.
4. State unverified chaining conditions and the exact operator handoff.
5. Extract reusable lessons as candidates with applicability and failure conditions.
6. Run `writeupcheck HANDOFF.md --strict` (or the selected output) before promotion and resolve all
   errors and warnings.

## Output shape

Use the sections from `doctrine/WRITEUP_FORMAT.md`:

1. Status and scope
2. Artifacts and environment
3. Summary
4. Analysis timeline
5. Primitive gate evidence
6. Local reproduction
7. Rejected routes
8. Constraints and operator handoff
9. Reusable knowledge
10. AI and automation disclosure

Keep raw terminal output in evidence artifacts and quote only the observations needed to verify
the conclusion. A complete exploit-to-flag script is not part of the default local handoff.

## Knowledge promotion

Write repo-owned lessons under `knowledge/learned/`; do not modify the vendored pwn/rev corpus.

- `candidate`: directly observed in one challenge
- `validated`: reproduced on an independent artifact or reviewed against a counterexample
- `reused`: successfully applied to another challenge

Every lesson must name its evidence, prerequisites, failure conditions, and promotion status.

## Challenge

$ARGUMENTS
