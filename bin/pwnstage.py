#!/usr/bin/env python3
# STATE v2 버스를 코드에서 소비 — evidence-backed 정적 오프셋 재사용 규약.
#   from pwnstage import offsets, get, set_offset
#   off = offsets(); system = libc_base + off["system"]     # 재계산(readelf/ROP) 금지
# CLI: pwnstage           -> 모든 검증 오프셋 나열
#      pwnstage get <k>    -> 단일 값(hex)
#      pwnstage scaffold   -> ./primitives.py 스켈레톤 생성
import os
from ratlib.state_v2 import trusted_offset_inputs, project_trusted_offsets
F = "STATE.jsonl"
def _root(path):
    p = os.path.abspath(path or F)
    if path in (None, F) or os.path.basename(p) == F:
        return os.path.dirname(p) or os.getcwd()
    if os.path.isdir(p):
        return p
    if p.endswith(os.path.join(".rat", "events", "STATE.v2.jsonl")):
        return os.path.dirname(os.path.dirname(os.path.dirname(p)))
    raise ValueError("pwnstage path must be a challenge directory, STATE.jsonl root hint, or STATE.v2.jsonl")
def offsets(path=F):
    "trusted STATE v2 pwn.offset observations -> {name:int}"
    root = _root(path)
    return project_trusted_offsets(*trusted_offset_inputs(root))
def get(k, default=None, path=F):
    return offsets(path).get(k, default)
def set_offset(k, v, src="", path=F):
    raise ValueError("pwnstage.set_offset is disabled; append a typed rat.observation/v1 kind=pwn.offset via `state event append`")
_TEMPLATE = '''# primitives.py — 이 챌린지의 검증된 primitive를 함수로 노출.
# 형제/후속 에이전트는 재도출 말고 `from primitives import *` 로 조립.
# 규칙: (1) primitive PASS는 typed rat.primitive/v1 문서로만 기록한다.
#       (2) ASLR 런타임값(heap_base/libc_base)은 캐시 불가 -> 매 실행 산출.
#       (3) 정적 오프셋은 evidence artifact를 가진 rat.observation/v1 kind=pwn.offset으로 저장한다.
#       (4) PASS에는 서로 다른 active direct SELF observation 3개와 input/environment sha256 digest가 필요하다.
import sys as _s, os as _o  # pwn.py shadow 방지: CWD를 sys.path서 제거 후 pwntools import
_s.path=[q for q in _s.path if _o.path.abspath(q or '.')!=_o.path.abspath(_o.getcwd())]
from pwn import *
import pwnstage

def leak_heap(io):
    "returns heap_base (per-run). TODO: 검증된 로직 이식."
    raise NotImplementedError

def leak_libc(io, heap_base):
    "returns libc_base (per-run)."
    raise NotImplementedError

def arb_write(io, addr, data):
    "arbitrary write primitive."
    raise NotImplementedError
'''
if __name__ == "__main__":
    import sys, shutil
    a = sys.argv[1:]
    if a and a[0] == "get" and len(a) > 1:
        try: v = get(a[1])
        except ValueError as e: print("[pwnstage:err] %s" % e, file=sys.stderr); raise SystemExit(2)
        print(hex(v) if isinstance(v, int) else "")
    elif a and a[0] == "scaffold":
        if os.path.exists("primitives.py"): print("primitives.py 이미 존재(스킵)")
        else: open("primitives.py","w").write(_TEMPLATE); print("[+] primitives.py 생성")
    else:
        try:
            for k, v in offsets().items(): print("%s=%#x" % (k, v))
        except ValueError as e:
            print("[pwnstage:err] %s" % e, file=sys.stderr); raise SystemExit(2)
