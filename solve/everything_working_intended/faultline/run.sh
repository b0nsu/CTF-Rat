#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
PROFILE=${1:-challenge}
case "$PROFILE" in challenge|calibration) ;; *) echo "usage: $0 [challenge|calibration]" >&2; exit 2;; esac
QEMU=${QEMU:-qemu-system-x86_64}
command -v "$QEMU" >/dev/null || { echo "qemu-system-x86_64 not found" >&2; exit 1; }

RUN_USER=${USER:-$(id -u)}
SOCK=${TMPDIR:-/tmp}/faultline-$RUN_USER-$$.sock
VARS=${TMPDIR:-/tmp}/faultline-vars-$RUN_USER-$$.fd
cp "$ROOT/OVMF_VARS.fd" "$VARS"
rm -f "$SOCK"
"$ROOT/chronicle_device" --socket "$SOCK" &
DEV_PID=$!
trap 'kill $DEV_PID 2>/dev/null || true; rm -f "$SOCK" "$VARS"' EXIT
for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.02; done

"$QEMU" \
  -machine pc,accel=tcg -cpu qemu64 -m 512M -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file="$ROOT/OVMF_CODE.fd" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive if=virtio,format=raw,readonly=on,file="$ROOT/esp.$PROFILE.img" \
  -display none -serial stdio \
  -chardev socket,id=chron,path="$SOCK" -serial chardev:chron \
  -no-reboot -net none
wait "$DEV_PID" || true
