# pwn-format

hot-path only — full technique catalog: `knowledge/ctf-skills/format-string.md`.

## SIGNALS
- Variadic printf-family import (`printf`, `fprintf`, `dprintf`, `syslog`) present alongside a user-input function (`read`/`gets`/`scanf`/`fgets`), suggesting user data can reach a format argument.

## FIRST ACTION
- Confirm the format string is actually user-controlled (not a fixed literal) via `decomp <bin> <func>` on the call site before assembling `%p`/`%n` payloads.
- `pwnleak` on a first `%p`-chain probe output to classify recovered pointers (stack/libc/PIE) before building the real leak chain.

## PIVOT
- The format argument is fixed/hardcoded (no actual injection) → re-route via `rat-profile`/`revq` signals to whatever the real primitive is (often `pwn-stack` or `pwn-heap`).
- Leak succeeds but overwrite path needs a stack-smash instead of `%n` → `pwn-stack`.

## ESCALATE
- GOT is fully RELRO'd and no other writable function-pointer target is visible → DEEP; do not guess a target, enumerate writable code pointers first.

## VERIFY
- `pwnpayload` to check the crafted format payload for bad bytes/terminator/transport truncation before sending.
- SOLVED requires an actual leaked value or overwrite effect observed from a real run (local or user-designated remote), not a predicted offset.
