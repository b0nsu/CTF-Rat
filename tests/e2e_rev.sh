#!/usr/bin/env bash
# e2e_rev.sh — rev 루프(revq/symsolve/vmlift) 로컬 통합 회귀검증.
#   이 환경에 gcc + native angr(.venv-angr, SETUP.md) 필요. 없으면 selftest만 돌고 e2e는 스킵.
#   (예전 WSL-SSH 방식 폐기 — 클론한 자리에서 로컬 실행.)
set -uo pipefail
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"; ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-python3}"
ANGR_PY="${RAT_ANGR_PYTHON:-$ROOT/.venv-angr/bin/python}"
REQUIRE_ENGINE=0
if [ "${1:-}" = "--require-engine" ]; then REQUIRE_ENGINE=1; fi
if [ ! -x "$ANGR_PY" ] && [ -z "${RAT_ANGR_PYTHON:-}" ]; then ANGR_PY="$PY"; fi
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FAIL=0
green(){ echo "  ✅ $1"; }
red(){ echo "  ❌ $1"; FAIL=1; }

echo "== selftest (순수 로직) =="
for t in bin/revq solve/_template/rev/symsolve.py solve/_template/rev/vmlift.py; do
  "$PY" "$ROOT/$t" selftest >/dev/null 2>&1 && green "selftest $t" || red "selftest $t"
done

if ! "$ANGR_PY" -c 'import angr; from angr.engines import UberEnginePcode; from angr.engines import unicorn; assert unicorn._UC_NATIVE is not None' >/dev/null 2>&1; then
  if [ "$REQUIRE_ENGINE" -eq 1 ]; then
    echo "[e2e_rev] native angr unavailable; required integration lane failed (SETUP.md)."
    exit 1
  fi
  echo "[e2e_rev] native angr venv 미설치 → 실-바이너리 e2e 스킵 (SETUP.md). selftest 만 평가."
  echo "-----"; [ $FAIL -eq 0 ] && { echo "PARTIAL GREEN (selftest only) ✅"; exit 0; } || { echo "FAIL ❌"; exit 1; }
fi

echo "== native Unicorn bridge (angr) =="
"$ANGR_PY" -c 'from angr.engines import UberEnginePcode; from angr.engines import unicorn; assert unicorn._UC_NATIVE is not None, "angr native Unicorn bridge is disabled"' \
  && green "angr _UC_NATIVE native bridge" || red "angr _UC_NATIVE native bridge"

echo "== 실-바이너리 e2e (angr) =="
cat > "$TMP/crackme.c" <<'C'
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){char b[16]={0};if(read(0,b,11)<0)return 1;
if(memcmp(b,"s3cr3t_p4ss",11)==0)puts("Correct");else puts("Wrong");return 0;}
C
gcc -O0 "$TMP/crackme.c" -o "$TMP/crackme" 2>/dev/null || { red "gcc 컴파일"; echo "FAIL ❌"; exit 1; }

RAT_ANGR_PYTHON="$ANGR_PY" "$ROOT/bin/symsolve" "$TMP/crackme" \
  --find-str Correct --stdin 11 --printable --record-state-dir "$TMP/state" >"$TMP/sym.out" 2>"$TMP/sym.err" || true
if grep -q 'native Unicorn option enabled' "$TMP/sym.err"; then green "symsolve Unicorn option"; else red "symsolve Unicorn option"; fi
if grep -q 's3cr3t_p4ss' "$TMP/sym.out"; then green "symsolve 복원(s3cr3t_p4ss)"; else red "symsolve 복원"; cat "$TMP/sym.out"; fi
if grep -q 'concrete-verify: ✅' "$TMP/sym.out"; then green "symsolve concrete-verify"; else red "symsolve concrete-verify"; fi
"$ANGR_PY" -c 'import json,sys; rows=[json.loads(x) for x in open(sys.argv[1])]; o=next(e["payload"] for e in rows if e["type"]=="observation.recorded"); p=next(e["payload"] for e in rows if e["type"]=="primitive.revised"); assert o["kind"]=="rev.symsolve.concrete-verify" and p["extensions"]["engine_observation_id"]==o["observation_id"] and p["extensions"]["solve_origin"]=="rev-symbolic" and p["producer"]["engine"]=="symsolve"' \
  "$TMP/state/.rat/events/STATE.v2.jsonl" \
  && green "symsolve STATE provenance" || red "symsolve STATE provenance"

"$ROOT/bin/revq" "$TMP/crackme" --format json >"$TMP/rev.json" 2>/dev/null
"$ANGR_PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["engine"] == "angr" and isinstance(d["functions"], list)' "$TMP/rev.json" \
  && green "revq dispatch + angr JSON map" || red "revq dispatch + angr JSON map"
"$ROOT/bin/rat" route "$TMP/crackme" --format json >"$TMP/route.json" 2>/dev/null
"$ANGR_PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["capabilities"]["angr"] is True and not d.get("diagnostics")' "$TMP/route.json" \
  && green "rat route native angr dispatch" || red "rat route native angr dispatch"
"$ROOT/bin/rat-doctor" "$TMP/crackme" --format json >"$TMP/doctor.json" 2>/dev/null
"$ANGR_PY" -c 'import json,sys; c=json.load(open(sys.argv[1]))["summary"]["capabilities"]; assert c["angr"]["status"]=="available" and c["pwntools"]["status"]=="available"' "$TMP/doctor.json" \
  && green "doctor sees both isolated stacks" || red "doctor sees both isolated stacks"

"$PY" "$ROOT/solve/_template/rev/vmlift.py" --solve 2>/dev/null | grep -q "b'ABCD'" \
  && green "vmlift oracle-brute" || red "vmlift oracle"

echo "-----"
[ $FAIL -eq 0 ] && echo "ALL GREEN ✅" || echo "FAIL ❌"
exit $FAIL
