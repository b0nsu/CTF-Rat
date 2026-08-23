#!/usr/bin/env bash
# CTF-Rat dev 컨테이너 빌드 (amd64 강제)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
docker build --platform linux/amd64 -t ctf-rat-dev:local docker/dev "$@"
