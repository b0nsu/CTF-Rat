#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qiling_trace — Windows PE/DLL 동적 에뮬레이션 스캐폴드 (RUNNER §6.1 rev 루프, Windows 축).

x64dbg 는 Windows 네이티브(Wine 억지구동 불안정 → 인터랙티브는 Windows VM). **Linux 호스트에서
PE 를 동적으로 볼 땐 Qiling(Unicorn 기반 에뮬레이션, Wine 불필요)** 이 정석. 이건 그 스캐폴드다.
`symsolve`(angr/ELF)·`vmlift`(VM)의 Windows 자매.

되는 것: PE 로드→에뮬 실행, stdin 주입, 출력 캡처, 성공/실패 문자열 확인, (선택) 콜 트레이스.
전제: **Windows rootfs**(에뮬용 DLL 집합) 필요. Qiling 저장소 예제 rootfs 또는 실제 시스템 DLL.
  pip install qiling  후  `python3 -c "import qiling,os;print(os.path.dirname(qiling.__file__))"` →
  examples/rootfs/x8664_windows (없으면 Qiling 문서의 rootfs 준비 절 참고).

사용:
  qiling_trace.py <pe> --rootfs DIR [--stdin S] [--find-str STR] [--calls] [--timeout SEC]
  qiling_trace.py selftest        # 순수 파서(qiling·PE 불필요)

실행:  python3 qiling_trace.py <pe> --rootfs <win_rootfs> --find-str Correct --stdin "guess"
"""
import argparse
import os
import sys


def resolve_rootfs(arg):
    """--rootfs 미지정 시 흔한 위치 추정 (Qiling 예제 rootfs)."""
    if arg:
        return arg
    try:
        import qiling
        base = os.path.join(os.path.dirname(qiling.__file__), "..", "examples", "rootfs")
        for cand in ("x8664_windows", "x86_windows"):
            p = os.path.normpath(os.path.join(base, cand))
            if os.path.isdir(p):
                return p
    except Exception:
        pass
    return None


def trace(args):
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except ImportError:
        print("[qiling_trace:err] qiling 미설치 — `pip install qiling` (SETUP.md Windows rev 절).",
              file=sys.stderr)
        return 2

    rootfs = resolve_rootfs(args.rootfs)
    if not rootfs or not os.path.isdir(rootfs):
        print("[qiling_trace:err] Windows rootfs 필요 — --rootfs <dir> 지정.\n"
              "  (Qiling 예제 rootfs 또는 시스템 DLL 모음. SETUP.md 참고.)", file=sys.stderr)
        return 2

    print("[qiling_trace] load %s (rootfs=%s)" % (args.binary, rootfs), file=sys.stderr)
    ql = Qiling([args.binary], rootfs, verbose=QL_VERBOSE.OFF)

    # stdin 주입 (crackme 가 stdin 을 읽는 경우)
    if args.stdin is not None:
        try:
            ql.os.stdin = _MemPipe((args.stdin + "\n").encode())
        except Exception:
            print("[qiling_trace] stdin 주입 실패(버전차) — EXTENSION 참고", file=sys.stderr)

    # 출력 캡처
    out = bytearray()
    try:
        ql.os.stdout = _CapPipe(out)
    except Exception:
        pass

    # (선택) 콜 트레이스: call 명령마다 대상 기록 (느림)
    calls = []
    if args.calls:
        def _hk(ql_, addr, size):
            calls.append(addr)
        try:
            ql.hook_code(_hk)
        except Exception:
            pass

    import threading
    done = {"ok": False}
    def _run():
        try:
            ql.run()
            done["ok"] = True
        except Exception as e:
            print("[qiling_trace] run 종료/예외: %s" % e, file=sys.stderr)
    t = threading.Thread(target=_run, daemon=True)
    t.start(); t.join(args.timeout)

    captured = bytes(out)
    print("[qiling_trace] 실행 %s (출력 %dB)" % ("완료" if done["ok"] else "타임아웃/중단", len(captured)))
    if captured:
        print("  stdout: %r" % captured[:300])
    if args.find_str:
        hit = args.find_str.encode() in captured
        print("  find-str %r: %s" % (args.find_str, "✅ 발견" if hit else "✗ 없음"))
        return 0 if hit else 1
    if args.calls:
        print("  call/instr hook 이벤트: %d" % len(calls))
    return 0


class _MemPipe:
    """qiling stdin 대체용 최소 read 파이프."""
    def __init__(self, data):
        self.buf = bytearray(data)
    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self.buf)
        chunk = bytes(self.buf[:n]); del self.buf[:n]
        return chunk


class _CapPipe:
    """qiling stdout 캡처용 최소 write 파이프."""
    def __init__(self, sink):
        self.sink = sink
    def write(self, b):
        self.sink.extend(b if isinstance(b, (bytes, bytearray)) else str(b).encode())
        return len(b)
    def flush(self):
        pass


# ─────────────────────────── selftest (순수, qiling·PE 무관) ───────────────────────────
def selftest():
    fails = []
    def chk(c, name):
        print(("  ✅ " if c else "  ❌ ") + name)
        if not c:
            fails.append(name)
    print("== qiling_trace selftest (순수 파서) ==")
    chk(resolve_rootfs("/my/rootfs") == "/my/rootfs", "resolve_rootfs: 인자 우선")
    p = _MemPipe(b"abc")
    chk(p.read(2) == b"ab" and p.read() == b"c", "_MemPipe read")
    sink = bytearray(); cp = _CapPipe(sink); cp.write(b"hi"); cp.write("!")
    chk(bytes(sink) == b"hi!", "_CapPipe write(bytes+str)")
    print("-" * 40)
    if fails:
        print("FAIL %d: %s" % (len(fails), ", ".join(fails))); return 1
    print("ALL GREEN ✅"); return 0


def build_parser():
    p = argparse.ArgumentParser(prog="qiling_trace", description="Qiling PE 동적 에뮬레이션")
    p.add_argument("binary", nargs="?")
    p.add_argument("--rootfs", help="Windows rootfs 디렉토리 (에뮬용 DLL)")
    p.add_argument("--stdin", help="주입할 stdin 문자열")
    p.add_argument("--find-str", help="출력에서 찾을 문자열(성공판정)")
    p.add_argument("--calls", action="store_true", help="명령/콜 hook 이벤트 카운트(느림)")
    p.add_argument("--timeout", type=float, default=60.0, help="실행 상한(기본 60s)")
    p.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    return p


def main(argv):
    if argv and argv[0] == "selftest":
        return selftest()
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.binary:
        build_parser().print_help(); return 2
    return trace(args)


# ══════════════════════════════════════════════════════════════════════════════
#  EXTENSION — CLI 로 안 되는 케이스 (버전차/복잡 로직) 여기 복사·편집.
#  1) 성공 분기 주소 hook 으로 직접 판정:
#       ql.hook_address(lambda ql: setattr(ql, "_win", True), 0x401234)
#  2) Win32 API 후킹(WriteConsoleA/strcmp 등) — 출력·비교 인자 가로채기:
#       from qiling.const import QL_INTERCEPT
#       ql.os.set_api("WriteConsoleA", on_write, QL_INTERCEPT.ENTER)
#  3) 특정 함수만 부분 실행: ql.run(begin=0x401000, end=0x401200)
#  4) 메모리/레지스터 조작 후 재개: ql.mem.write(addr, b"..."); ql.reg.rax = 0
#  5) anti-emulation(rdtsc/PEB) 우회는 knowledge/ctf-reverse/anti-analysis.md 참고.
#  ※ rootfs 준비/Windows API 커버리지는 Qiling 문서. il2cpp/.NET 은 ilspycmd 로 별도.
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
