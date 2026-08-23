# pwn-stack

hot-path only — full technique catalog: `knowledge/ctf-skills/overflow-basics.md`.

## SIGNALS
- `recon`/profile flags an overflow-prone import (`gets`, `strcpy`, `strcat`, `sprintf`) and `elf.nx == false` (shellcode-on-stack still viable).

## FIRST ACTION
- `pwncalc` for offsets/alignment, `pwnropcheck` to confirm the stack region is actually executable and mapped as expected before assembling anything.
- Confirm the overflow's controlled length with a cyclic pattern locally (`pwncrash`) — do not assume the source-read length.

## PIVOT
- `elf.nx == true` → shellcode is blocked, switch to `pwn-rop`.
- The overflow is heap-allocated (buffer inside a malloc'd struct), not a stack frame → `pwn-heap`.
- The primitive turns out to be format-string driven, not a raw overflow → `pwn-format`.

## ESCALATE
- Canary present and no leak path yet → DEEP; do not brute-force the canary probabilistically per this repo's reproducibility rule (`doctrine/SOLVING.md`).
- Offset uncertain after one `pwncrash` pass → re-measure, do not copy example offsets from knowledge docs.

## VERIFY
- `state primitive <name> pass <evidence>` only after the minimal payload demonstrably controls EIP/RIP (or a marker/terminator) in a plain local run — per `doctrine/PRIMITIVE_GATE.md`.
- SOLVED requires the assembled exploit to run against the local process/Docker (or the user's designated remote) and produce the real flag/shell.
