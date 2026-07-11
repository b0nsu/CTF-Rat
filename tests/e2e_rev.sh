#!/usr/bin/env bash
# e2e_rev.sh — rev 루프(revq/symsolve/vmlift) 로컬 통합 회귀검증.
#   이 환경에 gcc + angr(SETUP.md) 필요. angr 없으면 selftest 만 돌고 실-바이너리 e2e 는 스킵.
#   (예전 WSL-SSH 방식 폐기 — 클론한 자리에서 로컬 실행.)
set -uo pipefail
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"; ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-python3}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FAIL=0
green(){ echo "  ✅ $1"; }
red(){ echo "  ❌ $1"; FAIL=1; }

echo "== selftest (순수 로직) =="
for t in bin/revq solve/_template/rev/symsolve.py solve/_template/rev/vmlift.py; do
  "$PY" "$ROOT/$t" selftest >/dev/null 2>&1 && green "selftest $t" || red "selftest $t"
done

if ! "$PY" -c 'import angr' >/dev/null 2>&1; then
  echo "[e2e_rev] angr 미설치 → 실-바이너리 e2e 스킵 (SETUP.md). selftest 만 평가."
  echo "-----"; [ $FAIL -eq 0 ] && { echo "PARTIAL GREEN (selftest only) ✅"; exit 0; } || { echo "FAIL ❌"; exit 1; }
fi

echo "== 실-바이너리 e2e (angr) =="
cat > "$TMP/crackme.c" <<'C'
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){char b[16]={0};if(read(0,b,11)<0)return 1;
if(memcmp(b,"s3cr3t_p4ss",11)==0)puts("Correct");else puts("Wrong");return 0;}
C
gcc -O1 -s "$TMP/crackme.c" -o "$TMP/crackme" 2>/dev/null || { red "gcc 컴파일"; echo "FAIL ❌"; exit 1; }

"$PY" "$ROOT/bin/revq" "$TMP/crackme" --json >"$TMP/rev.json" 2>/dev/null
grep -q '"engine": "angr"' "$TMP/rev.json" && green "revq angr 추출" || red "revq angr 추출"
"$PY" "$ROOT/bin/revq" "$TMP/crackme" --interesting 2>/dev/null | grep -Eq 'Correct|memcmp' \
  && green "revq interesting 지목" || red "revq interesting"

"$PY" "$ROOT/solve/_template/rev/symsolve.py" "$TMP/crackme" \
  --find-str Correct --avoid-str Wrong --stdin 11 --printable >"$TMP/sym.out" 2>/dev/null || true
grep -q 's3cr3t_p4ss' "$TMP/sym.out" && green "symsolve 복원(s3cr3t_p4ss)" || red "symsolve 복원"
grep -q 'concrete-verify: ✅' "$TMP/sym.out" && green "symsolve concrete-verify" || red "symsolve concrete-verify"

"$PY" "$ROOT/solve/_template/rev/vmlift.py" --solve 2>/dev/null | grep -q "b'ABCD'" \
  && green "vmlift oracle-brute" || red "vmlift oracle"

echo "-----"
[ $FAIL -eq 0 ] && echo "ALL GREEN ✅" || echo "FAIL ❌"
exit $FAIL
