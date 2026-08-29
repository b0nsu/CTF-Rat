# pwn-stack

hot-path only — full technique catalog: `knowledge/ctf-skills/overflow-basics.md`.

## SIGNALS
- `recon`/`rat route` flags an overflow-prone import and `elf.nx == false` (shellcode-on-stack still viable). Strong/unbounded sinks: `gets`, `strcpy`, `strcat`, `sprintf`, `scanf` family. Weaker/bounded-capable sinks routed here as a heuristic: `read`, `memcpy`, `fgets`, `fread` — with these, confirm the read length is actually unbounded (source or `pwncrash`) before treating the overflow as real.

## FIRST ACTION
- `pwncalc` for offsets/alignment, `pwnropcheck` to confirm the stack region is actually executable and mapped as expected before assembling anything.
- Confirm the overflow's controlled length with a cyclic pattern locally (`pwncrash`) — do not assume the source-read length.

## PIVOT
- If `rat route` set `conflict: true`, a sibling pwn subroute matched the imports too — check its `alternatives` before committing (heap/format/overflow sinks can coexist).
- `elf.nx == true` → shellcode is blocked, switch to `pwn-rop`.
- The overflow is heap-allocated (buffer inside a malloc'd struct), not a stack frame → `pwn-heap`.
- The primitive turns out to be format-string driven, not a raw overflow → `pwn-format`.

## ESCALATE
- Canary present and no leak path yet → DEEP; do not brute-force the canary probabilistically per this repo's reproducibility rule (`doctrine/SOLVING.md`).
- Offset uncertain after one `pwncrash` pass → re-measure, do not copy example offsets from knowledge docs.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`) only after the minimal payload demonstrably controls EIP/RIP (or a marker/terminator) in a plain local run.
- SOLVED requires the assembled exploit to run against the local process/Docker (or the user's designated remote) and produce the real flag/shell.
