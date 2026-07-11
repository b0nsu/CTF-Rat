#!/usr/bin/env python3
# STATE 버스를 코드에서 소비 — 정적 오프셋 measure-once/read-many + primitive 재사용 규약.
#   from pwnstage import offsets, get, set_offset
#   off = offsets(); system = libc_base + off["system"]     # 재계산(readelf/ROP) 금지
#   set_offset("pop_rdi", g, "ROP(libc)")                    # 코드가 실측 오프셋을 버스에 영속
# CLI: pwnstage           -> 모든 검증 오프셋 나열
#      pwnstage get <k>    -> 단일 값(hex)
#      pwnstage scaffold   -> ./primitives.py 스켈레톤 생성
import os, json, fcntl, time
F = "STATE.jsonl"
def _toint(v):
    if isinstance(v, int): return v
    s = str(v).strip()
    for base in (0, 16):
        try: return int(s, base)
        except: pass
    return None
def offsets(path=F):
    "verified offsets from STATE.jsonl -> {name:int}"
    d = {}
    if not os.path.exists(path): return d
    for ln in open(path):
        ln = ln.strip()
        if not ln: continue
        try: e = json.loads(ln)
        except: continue
        if e.get("t") == "offset":
            iv = _toint(e.get("v"))
            if iv is not None: d[e["k"]] = iv   # 마지막 값이 이김
    return d
def get(k, default=None, path=F):
    return offsets(path).get(k, default)
def set_offset(k, v, src="", path=F):
    "programmatic append (mirrors `state offset`)"
    vs = v if isinstance(v, str) else hex(v)
    with open(path, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.write(json.dumps({"t":"offset","k":k,"v":vs,"src":src,"ts":int(time.time())},
                            ensure_ascii=False) + "\n")
        fcntl.flock(fh, fcntl.LOCK_UN)
_TEMPLATE = '''# primitives.py — 이 챌린지의 검증된 primitive를 함수로 노출.
# 형제/후속 에이전트는 재도출 말고 `from primitives import *` 로 조립.
# 규칙: (1) 각 함수는 담기 전에 로컬 실증(=`state ok`)될 것.
#       (2) ASLR 런타임값(heap_base/libc_base)은 캐시 불가 -> 매 실행 산출.
#       (3) 정적 오프셋은 `state offset`/`pwnstage.set_offset` 로 버스에 저장, `pwnstage.offsets()` 로 읽어 재계산 금지.
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
        v = get(a[1]); print(hex(v) if isinstance(v, int) else "")
    elif a and a[0] == "scaffold":
        if os.path.exists("primitives.py"): print("primitives.py 이미 존재(스킵)")
        else: open("primitives.py","w").write(_TEMPLATE); print("[+] primitives.py 생성")
    else:
        for k, v in offsets().items(): print("%s=%#x" % (k, v))
