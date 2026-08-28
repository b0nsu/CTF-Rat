# rev-vm

hot-path only — full technique catalog: `knowledge/ctf-reverse/patterns-runtime.md`.

## SIGNALS
- Function/string names or bodies hint at `vm`/`opcode`/`bytecode`/`dispatch`/`interpreter`.
- Many small, structurally-similar functions with no single obvious checker; a central dispatch loop over an instruction array.

## FIRST ACTION
- `solve/_template/rev/vmlift.py --disasm` against the suspected bytecode blob to confirm an instruction set exists before hand-reversing.
- `revq <bin> --func <dispatch-loop>` for the loop's neighbor card.

## PIVOT
- The "instructions" turn out to be a single memcmp/strcmp check dressed up → `rev-checker`.
- The blob is actually packed/encrypted data, not bytecode → `rev-packed`.

## ESCALATE
- Instruction set is large/irregular (not a small enum) → DEEP; consider a scout subagent for the opcode table before committing to a lifter.
- Oracle needed for solve is arithmetic/constraint-heavy on VM registers → `rev-symbolic` via `vmlift.py --solve` (oracle-brute) instead of hand-solving.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`, ≥3 active+direct SELF observations) is required before declaring SOLVED, in addition to the emulator/real-binary cross-check below.
- `vmlift.py --solve` (or hand-derived input) must be re-executed by the *emulator/lifter* and, where possible, cross-checked against the real binary's VM.
- Do not claim SOLVED from lifter output alone if the real binary's VM was never exercised with the same bytes.
