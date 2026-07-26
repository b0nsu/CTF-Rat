# pwnable.kr progress

Scope: `pwnable.kr/play.php`, Grotesque and above. Do not auto-submit flags.

## Operating notes

- Treat each challenge as a fresh solve to avoid wasting context.
- Do not reprint full CTF-RAT doctrine or skill files unless the workflow changes.
- Exclude challenges with existing local attempts unless explicitly resumed.
- For each solved challenge, leave only `STATE.jsonl`, `solve.py`, and `WRITEUP.md` in its `solve/pwnable-*` directory.
- Token/time reporting is tracked by the active Codex goal when available, not by repository automation. Use `get_goal` for the current session values.

Last observed goal usage:

- Status: paused
- Tokens used: 116083
- Elapsed seconds: 578

## Challenge status

| Challenge | Remote status | Local status | Directory | Notes |
|---|---:|---:|---|---|
| rootkit | not submitted | solved | `solve/pwnable-rootkit` | Flag verified locally from remote QEMU; no auto-submit. |
| wtf | not submitted | solved | `solve/pwnable-wtf` | Flag verified from `pwnable.kr:10039`; no auto-submit. |
| ascii | unknown | attempted | `solve/pwnable-ascii` | Existing attempt; exclude unless explicitly resumed. |
| elf | unknown | partial | `solve/pwnable-elf` | Interrupted during fetch; do not count as active solve unless resumed. |

