#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: desktop/dev.sh <challenge-dir> [solver-command]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHALLENGE="$(cd "$1" && pwd)"
SOLVER_COMMAND="${2:-}"

args=(python3 "$ROOT/bin/ratd" --challenge "$CHALLENGE")
if [[ -n "$SOLVER_COMMAND" ]]; then
  args+=(--solver-command "$SOLVER_COMMAND")
fi

"${args[@]}" &
RATD_PID=$!
cleanup() {
  kill "$RATD_PID" 2>/dev/null || true
  wait "$RATD_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cd "$ROOT/desktop"
npm run tauri dev
