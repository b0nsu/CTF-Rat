# rev-packed

hot-path only — full technique catalog: `knowledge/ctf-reverse/anti-analysis-ctf.md` (+`anti-analysis.md`).

## SIGNALS
- `revq` EVASION line: packer section name (e.g. UPX), high Shannon entropy (>=7.2/8), or anti-debug imports/strings (`ptrace`, `/proc/self/status`, `ld_preload`).

## FIRST ACTION
- Do not trust static function/string extraction yet — it is likely incomplete or obfuscated.
- `gdbq <bin> "b *_start" "run"` or a supervised dynamic run to reach the unpacked/decrypted state before re-running `revq --refresh`.

## PIVOT
- Once unpacked and `revq` shows a clear checker/VM signal, hand off to `rev-checker`/`rev-vm`/`rev-symbolic` as normal — this skill's job is only to get past the packing layer.

## ESCALATE
- Anti-debug traps (ptrace self-attach, timing checks) actively interfere with dynamic tracing → DEEP, `doctrine/PRIMITIVE_GATE.md` before assembling any bypass.
- Static results before and after unpacking materially disagree → DEEP; do not average or guess, re-measure.

## VERIFY
- Any offset/string/function claim made from a packed static read must be re-confirmed after unpacking, in the real process (`gdbq` observation or post-unpack `revq --refresh`).
- SOLVED requires evidence gathered from the *unpacked, running* binary, not the packed static image.
