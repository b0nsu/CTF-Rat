# primitives.py — 이 챌린지의 검증된 primitive를 함수로 노출.
# 형제/후속 에이전트는 재도출 말고 `from primitives import *` 로 조립.
# 규칙: (1) primitive PASS 전에는 typed candidate를 만들고, 서로 다른 active/direct SELF
#              observation 세 개와 evidence artifact, sha256 input/environment digest를 연결할 것.
#       (2) ASLR 런타임값(heap_base/libc_base)은 캐시 불가 -> 매 실행 산출.
#       (3) 재사용할 정적 오프셋은 typed `rat.observation/v1` (`kind:"pwn.offset"`)으로
#              기록하고 `pwnstage.offsets()`로만 읽는다. `state offset`과
#              `pwnstage.set_offset()`은 legacy 경로라 사용할 수 없다.
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
