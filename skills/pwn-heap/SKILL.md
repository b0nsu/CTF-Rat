# pwn-heap

hot-path only — full technique catalog: `knowledge/ctf-skills/heap-techniques.md` (+`heap-techniques-2.md`, `heap-fsop.md`).

## SIGNALS
- `malloc`/`free`/`calloc`/`realloc` present in imports; typically a menu-style CRUD binary (create/edit/delete/show).

## FIRST ACTION
- `decomp <bin> <func>` on each menu action to map allocation sizes and whether pointers are cleared after `free` (UAF) or reused (double-free).
- `gdbq` heap breakpoints (`b *free`, `b *malloc`) to observe real chunk layout before hypothesizing a house-of-* technique.
- Identify the libc version in play (`reference/glibc/`) — tcache/safe-linking behavior is version-gated.

## PIVOT
- No real heap bug (allocator calls present but no UAF/double-free/overflow reachable) → re-route from `rat-profile`/`revq` signals to the actual primitive.
- Bug is really a stack overflow inside a heap-allocated struct copy → `pwn-stack` primitive mechanics still apply once the vuln is pinned down.

## ESCALATE
- glibc version/tcache-safe-linking behavior uncertain → DEEP; confirm via `reference/glibc/` + local Docker before picking a house-of-* technique, per `knowledge/GROUNDING_INDEX.md` (how2heap gate).
- Multiple plausible corruption targets (vtable vs GOT vs tcache key) → DEEP, gate on `doctrine/SOLVABILITY.md` before committing.

## VERIFY
- `state primitive <name> pass <evidence>` only after the minimal heap manipulation demonstrably corrupts a controlled marker in a plain local run.
- SOLVED requires the exploit to reproduce against the actual libc/loader in play (local Docker/loopback matching the challenge's libc, or the user's designated remote).
