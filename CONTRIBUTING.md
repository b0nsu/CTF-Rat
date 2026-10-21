# Contributing to CTF-Rat

Thanks for considering a contribution. This repo is a pwn/rev CTF solving kit
built for AI coding agents (Claude Code, Codex) — tools, doctrine, and
knowledge live together so they stay in sync.

## Before you start

1. Read [README.md](README.md) for the overall flow and [CLAUDE.md](CLAUDE.md)
   for the operating rules agents follow in this repo.
2. Run [SETUP.md](SETUP.md) once to get a working environment
   (venv + angr + pwntools, Ghidra, glibc-fetch).
3. Confirm the baseline is green before you branch:
   ```sh
   python3 bin/rat selftest
   python3 bin/revq selftest
   python3 -m unittest discover -s tests -p 'test_*.py'
   ```

## Workflow

- Branch off `dev`, not `main`. `main` only receives reviewed, CI-green PRs.
- Keep PRs scoped to one change (one tool, one bug, one doc fix). Large
  unrelated diffs are hard to review and hard to revert.
- If you touch a tool under `bin/` or `solve/_template/rev/`, run its
  `selftest` and the relevant `tests/e2e_*` script before opening a PR — see
  the **Tests** section in [README.md](README.md) for the full list.
- Don't commit challenge binaries, flags, or credentials. Local artifacts and
  scratch state belong outside the repo (see `.gitignore`).

## Pull requests

- Open PRs against `main` using the PR template — describe what changed and
  why, and list which selftests/tests you ran.
- CI (`regression` + `analysis-deep` on PRs into `main`) must pass.
- At least one review approval is required before merge (branch protection
  enforces this, including for maintainers).
- Prefer squash merges — keep `main` history one commit per PR.

## Reporting issues

Use the issue templates (bug report / feature request).

## Code style

- No comments explaining *what* code does — only *why*, when it's genuinely
  non-obvious (a workaround, an invariant, a constraint).
- Match existing patterns in the file you're editing before introducing a new
  one.
- Keep tool output machine-parseable where the tool already supports
  `--format json`; don't grep/sed human-readable text output.
- Don't put issue/PR numbers, internal review markers (e.g. `R2-8`), or a
  specific challenge's analysis history in generated files or CLI help text —
  those reach end users. A comment that needs the *why* states the reusable
  condition or invariant directly instead of pointing at a ticket number.
- In source/tests/docs, an issue number is fine only as a single-line
  reference in a test docstring or a workaround comment — don't narrate the
  issue's history around it.
- Don't state an issue's status ("still open", "unresolved") in code or docs;
  it goes stale as soon as the issue closes. The issue tracker is the source
  of truth for status.
- Don't bake an issue number into a filename or function name (e.g.
  `test_issue_112_*`); name things after what they test, not the ticket that
  prompted them.
