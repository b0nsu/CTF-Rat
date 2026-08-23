#!/usr/bin/env bash
# 컨테이너에서 canonical selftest + full unittest 1회 실행
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec docker run --rm --platform linux/amd64 \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD":/work -w /work ctf-rat-dev:local bash -lc '
    set -e
    python3 bin/revq selftest
    python3 solve/_template/rev/symsolve.py selftest
    python3 -m unittest discover -s tests -p "test_*.py"
  '
