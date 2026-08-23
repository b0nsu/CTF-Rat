# pwn-rop

hot-path only — full technique catalog: `knowledge/ctf-skills/rop-and-shellcode.md` (+`rop-advanced.md`).

## SIGNALS
- Same overflow-prone imports as `pwn-stack`, but `elf.nx == true` — shellcode-on-stack is blocked, control flow must be redirected through existing code (ROP/ret2libc).

## FIRST ACTION
- `pwnropcheck` to validate gadget/mapping assumptions (code segment mapped, SysV stack alignment) before chaining.
- Identify PIE/RELRO/canary state first (`recon`) — it decides whether a leak stage is required before the ROP chain.

## PIVOT
- A leak is needed first and the primitive for getting it is format-string based → `pwn-format` for that stage, then return here for the chain.
- NX turns out to be off after re-measurement → `pwn-stack` (shellcode is simpler than a chain when available).

## ESCALATE
- No usable one-gadget / `system()` args reachable and libc identification is uncertain → DEEP; pin the libc via `reference/glibc/` before building the chain.
- Stack alignment (`movaps` faults) or bad-byte constraints keep breaking the chain → DEEP, `pwnpayload` + `pwnropcheck` full recheck rather than trial-and-error resending.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`) only after a minimal chain demonstrably redirects control flow (e.g. to a marker function) in a plain local run.
- SOLVED requires the full chain to execute against the local process/Docker (matching libc) or the user's designated remote, with the real flag/shell as evidence.
