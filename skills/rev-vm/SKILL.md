# rev-vm

hot-path only — full technique catalog: `knowledge/ctf-reverse/patterns-runtime.md`.

## SIGNALS
- Function/string names or bodies hint at `vm`/`opcode`/`bytecode`/`dispatch`/`interpreter`.
- Many small, structurally-similar functions with no single obvious checker; a central dispatch loop over an instruction array.

## FIRST ACTION
- Locate candidate functions with `rat query graph <bin>` if the dispatch function is unknown; use a bounded function card or `decomp <bin> <dispatch-loop>` to inspect opcode fetch, operand widths, and handler semantics. A call graph alone does not prove a VM.
- `vmlift` is a toy-VM scaffold. Copy it to the challenge workspace and adapt `VM_SPEC` and handlers to measured target semantics before decoding a target blob; an unadapted listing cannot confirm an instruction set.
- Cross-check decoded instructions against the target handler behavior before using the adapted lifter as an oracle.

## PIVOT
- The "instructions" turn out to be a single memcmp/strcmp check dressed up → `rev-checker`.
- The blob is actually packed/encrypted data, not bytecode → `rev-packed`.

## ESCALATE
- Instruction set is large/irregular (not a small enum) → DEEP; consider a scout subagent for the opcode table before committing to a lifter.
- Arithmetic/constraint-heavy VM logic → derive constraints from measured handlers and choose a suitable solver. The stock `vmlift --solve` is a bounded toy-VM brute-force reference, not a general symbolic solver.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`, ≥3 active+direct SELF observations) is required before declaring SOLVED, in addition to the emulator/real-binary cross-check below.
- Re-execute recovered input with the target-adapted emulator/lifter and cross-check the same bytes against the real binary's VM before declaring SOLVED.
- Do not claim SOLVED from lifter output alone if the real binary's VM was never exercised with the same bytes.
