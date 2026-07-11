# primitives.py — 이 챌린지의 검증된 primitive를 함수로 노출.
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
