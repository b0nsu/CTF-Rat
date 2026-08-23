#!/usr/bin/env bash
# 레포를 /work 로 마운트한 대화형 셸 (ptrace 허용)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec docker run --rm -it --platform linux/amd64 \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD":/work -w /work ctf-rat-dev:local "$@"
