#!/usr/bin/env python3
# LLM-driven pwn 용 compact 구조화 gdb 헬퍼.
#  - import: from pwnkit import CLEAN_GS, snapscript
#      gs = CLEAN_GS + snapscript([("rip","$rip"),("tgt","*(void**)%d"%a)]) + "\ncontinue\n"
#      -> stdout 에 'SNAP rip=0x...' 라인만 (pwndbg context/색상 대신 핀포인트 값).
#  - filter:  ... | pwnclean       (ANSI/배너/systemd/빈줄 제거)
#             ... | pwnclean --kv   (SNAP/PWNED/flag/uid/$ 신호 라인만)
import re, sys
CLEAN_GS = (
    "set pagination off\n"
    "set confirm off\n"
    "set height 0\n"
    "set width 0\n"
    "set context-sections ''\n"   # pwndbg: context 패널 끔
)
_GS_CORE = "set pagination off\nset confirm off\nset height 0\nset width 0\n"

def snapscript(pairs):
    "pairs: [(name, gdb_expr), ...] -> 'SNAP name=<hex>' 방출 gdbscript"
    out = []
    for name, expr in pairs:
        out.append('printf "SNAP %s=%%#lx\\n", %s' % (name, expr))
    return "\n".join(out) + "\n"

def run_batch(binary, script, stdin=b"", timeout=60, pwndbg=False):
    "headless scripted gdb via gdb -batch (SSH-safe). gdb.debug(gdbscript=) needs a terminal so SNAP is lost; use this. returns (snaps, raw)."
    import tempfile, os as _o, re as _r
    from ratlib.runner import run
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(((CLEAN_GS if pwndbg else _GS_CORE)) + script); sp = f.name  # pwndbg=True면 .gdbinit 로드(tcachebins/heap 사용가능)
    try:
        argv = (["gdb","-q","-batch","-x",sp,binary] if pwndbg else
                ["gdb","-q","-nx","-batch","-x",sp,binary])
        pr = run(argv, timeout_seconds=timeout, input_bytes=stdin, tool_version="gdb")
        raw = (pr.stdout.preview + pr.stderr.preview).decode("latin1")
        if pr.timed_out:
            raw += "\n[pwnkit] TIMEOUT\n"
    finally:
        try: _o.unlink(sp)
        except: pass
    snaps = {}
    for ln in raw.splitlines():
        m = _r.match(r"SNAP (\S+)=(\S+)", ln)
        if m:
            try: snaps[m.group(1)] = int(m.group(2), 0)
            except: snaps[m.group(1)] = m.group(2)
    return snaps, raw
_ANSI = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]')
_DROP = re.compile(r'(systemd user session|pwndbg:|Loaded .* pwndbg|Reading symbols|'
                   r'no debugging symbols|Thread debugging using|Using host libthread_db|'
                   r'^\s*$)')
_KV   = re.compile(r'(^SNAP |PWNED|flag\{|uid=|gid=|\[SHELL|\$\s)')
def _filter(kv_only=False):
    for raw in sys.stdin:
        s = _ANSI.sub('', raw.rstrip('\n'))
        if _DROP.search(s): continue
        if kv_only and not _KV.search(s): continue
        print(s)
if __name__ == "__main__":
    _filter(kv_only=("--kv" in sys.argv))
