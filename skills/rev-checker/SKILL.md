# rev-checker

hot-path only — full technique catalog: `knowledge/ctf-reverse/patterns-ctf.md` (+`patterns-ctf-2.md`, `patterns-ctf-3.md`).

## SIGNALS
- `revq --interesting` top candidate calls `memcmp`/`strcmp`/`strncmp` directly ("비교함수 호출").
- Success/fail literal strings referenced near the compare call.

## FIRST ACTION
- PE/DLL이면(`revq` 배너에 `PLATFORM: PE/Windows`) 정적은 `decomp`/`revq` 그대로, 동적은 `solve/_template/rev/qiling_trace.py`(Qiling, rootfs 필요 — SETUP §8) — gdbq/symsolve 직행 금지.
- `revq <bin> --func <interesting-top>` for the neighbor card (calls/callers/strings, no full decompile).
- If the literal is short and directly compared: read it, no solver needed.

## PIVOT
- Compare is against a transformed value (xor/add/custom encode), not a raw literal → `rev-symbolic`.
- No direct cmp call, only a dispatch loop over opcodes → `rev-vm`.
- High entropy / packer section on the binary itself → `rev-packed`.

## ESCALATE
- Interesting-candidate list is ambiguous (multiple similar-score functions) → DEEP, `doctrine/SOLVABILITY.md` gate before committing.
- Static-only reading conflicts with observed runtime behavior → DEEP, cross-verify with `gdbq`.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`, ≥3 active+direct SELF observations) plus concrete-verify are both required before declaring SOLVED; a solver result alone is a hypothesis.
- `symsolve.py --find-str <success> --avoid-str <fail>` with concrete-verify (real binary re-execution), or a hand-derived literal re-run through the real binary.
- `SOLVED`/PASS requires the recovered input to actually produce the success path when fed to the unmodified binary.
