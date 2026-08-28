# rev-symbolic

hot-path only — full technique catalog: `knowledge/ctf-reverse/patterns-ctf.md`, `patterns-ctf-2.md`, `patterns-ctf-3.md`.

## SIGNALS
- `revq --interesting` finds a checker-like function, but it does *not* call `memcmp`/`strcmp` directly — the compare is preceded by arithmetic/bitwise transforms on the input, or crypto-hint tokens (xor/aes/base64/crc/...) appear near it.

## FIRST ACTION
- `symsolve.py <bin> --find-str <success> --avoid-str <fail> --stdin <n> --printable` — let angr solve the transform instead of hand-deriving it.
- If the transform is a small custom encoding rather than real crypto, hand-derivation from `decomp <bin> <func>` is often faster than symbolic execution; try both, keep whichever concrete-verifies first.

## PIVOT
- angr times out or the state space explodes (e.g. calls into libc crypto or has heavy loops) → narrow the target function first (`--func` neighbor card) or fall back to hand-derivation from decompilation.
- Turns out to be a straight literal compare after all → `rev-checker`.

## ESCALATE
- Symbolic execution genuinely stuck (unresolved indirect calls, path explosion) after narrowing → DEEP, scout-subagent read of the decompiled function before retrying.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`, ≥3 active+direct SELF observations) is required before declaring SOLVED, in addition to concrete-verify below.
- `symsolve.py` concrete-verify (recovered input re-run through the real binary, not just the solver's symbolic state) is the only acceptable evidence for SOLVED here.
- A symbolic solution that only satisfies angr's model without concrete-verify is a hypothesis, not a primitive PASS.
