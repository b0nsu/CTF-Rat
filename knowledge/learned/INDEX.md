# Locally learned knowledge

This directory contains repo-owned lessons distilled from locally verified challenge work. It is
kept separate from the vendored `ctf-skills` and `ctf-reverse` corpora.

## Promotion states

| State | Requirement |
|---|---|
| `candidate` | Direct evidence from one supplied challenge |
| `validated` | Independent artifact reproduction or explicit counterexample review |
| `reused` | Applied successfully to a different challenge |

Create one focused file per pattern under `pwn/` or `rev/`, using `TEMPLATE.md`. Index only lessons
that have an evidence path and explicit applicability and failure conditions.

## Rev

| Pattern | Status | Source | Evidence |
|---|---|---|---|
| [Relocation-Hidden Pre-Main Wrapper](rev/relocation-hidden-premain.md) | `candidate` | `unsat` | `/work/solve/unsat/.rat/events/STATE.v2.jsonl` |
| [Table-Encoded GF(16) Runtime](rev/table-encoded-gf16-runtime.md) | `candidate` | `chorus` | `/work/solve/chorus/HANDOFF.md` |
