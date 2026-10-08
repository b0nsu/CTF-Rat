# rev-packed

hot-path only — full technique catalog: `knowledge/ctf-reverse/anti-analysis-ctf.md` (+`anti-analysis.md`).

## SIGNALS
- `revq` EVASION line: packer section name (e.g. UPX), high Shannon entropy (>=7.2/8), or anti-debug imports/strings (`ptrace`, `/proc/self/status`, `ld_preload`).

## FIRST ACTION
- PE/DLL이면(`revq` 배너에 `PLATFORM: PE/Windows`) 정적은 `decomp`/`revq` 그대로, 동적 언팩 관찰은 `solve/_template/rev/qiling_trace.py`(Qiling, rootfs 필요 — SETUP §8) — gdbq/symsolve 직행 금지.
- Do not trust static function/string extraction yet — it is likely incomplete or obfuscated.
- If the EVASION line names UPX (or `upx -t <bin>` succeeds): unpack statically first — `upx -d -o <bin>.unpacked <bin>`, then `revq --refresh <bin>.unpacked`. This is deterministic and skips dynamic tracing.
- Otherwise (custom/unknown packer): breaking at `*_start` lands you *before* the unpacking stub runs — that is the wrong moment. Run to the OEP (original entry point) instead: let the stub decrypt, then break after the tail jump into the unpacked code (e.g. `gdbq <bin> "b *<OEP>" "run"` once the OEP is found via a hardware-write watchpoint on the target segment, or single-step the final `jmp`/`ret` out of the stub). Only then dump/`revq --refresh` the unpacked image.

## PIVOT
- Once unpacked and `revq` shows a clear checker/VM signal, hand off to `rev-checker`/`rev-vm`/`rev-symbolic` as normal — this skill's job is only to get past the packing layer.

## ESCALATE
- Anti-debug traps (ptrace self-attach, timing checks) actively interfere with dynamic tracing → DEEP, `doctrine/PRIMITIVE_GATE.md` before assembling any bypass.
- Static results before and after unpacking materially disagree → DEEP; do not average or guess, re-measure.

## VERIFY
- Any offset/string/function claim made from a packed static read must be re-confirmed after unpacking, in the real process (`gdbq` observation or post-unpack `revq --refresh`).
- SOLVED requires evidence gathered from the *unpacked, running* binary, not the packed static image.
