#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
symsolve — angr symbolic 하니스 (rev 루프).

"제약 풀이를 서브에이전트에 위임"하는 스캐폴드. **흔한 crackme 는 코드 수정 없이
CLI 인자만으로** 풀리고, 복잡한 경우(훅·simprocedure·커스텀 제약)는 아래
EXTENSION 지점을 편집한다.

revq 와 같은 angr 로드 베이스(PIE=0x400000)를 쓰므로 **revq 가 찍은 주소를
`--find`/`--avoid` 에 그대로** 넣으면 된다:
    revq crackme --interesting        # → 후보 함수/주소
    symsolve crackme --find-str Correct --stdin 32 --printable

사용:
  symsolve <bin> --find-str <STR>            # stdout 에 STR 뜨는 입력 탐색 (가장 흔함)
  symsolve <bin> --find <ADDR> [--avoid A..] # 주소 도달/회피
  symsolve <bin> --avoid-str <STR>           # 실패 메시지 회피
  입력원: --stdin N(기본32) | --arg N(argv[1]) | --file PATH:N
  제약  : --printable | --charset "0-9a-f" | --no-null
  기타  : --base 0xADDR(로드베이스 재지정) | --timeout SEC | --selftest

예:
  symsolve ./crackme --find-str "Correct" --stdin 16 --printable
  symsolve ./crackme --find 0x401234 --avoid 0x4012a0 --arg 20 --charset "0-9A-Za-z_"

실행:  python3 symsolve.py <bin> ...  (angr 설치 venv, SETUP.md 참고)
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time


# ─────────────────────────── charset 파서 (순수, selftest 대상) ───────────────────────────
def expand_charset(spec):
    """'0-9a-f_' → 허용 바이트 정렬 리스트. 범위(a-z)·개별문자 혼용."""
    out = set()
    i = 0
    while i < len(spec):
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = ord(spec[i]), ord(spec[i + 2])
            if lo <= hi:
                out.update(range(lo, hi + 1))
            i += 3
        else:
            out.add(ord(spec[i]))
            i += 1
    return sorted(out)


def parse_file_spec(spec):
    """'PATH:N' → (path, nbytes). N 없으면 (path, None)."""
    if ":" in spec:
        p, n = spec.rsplit(":", 1)
        if n.isdigit():
            return p, int(n)
    return spec, None


def parse_addr(s):
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        return None


# ─────────────────────────── 솔버 본체 (angr lazy-import) ───────────────────────────
def solve(args):
    import logging
    for n in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(n).setLevel(logging.ERROR)
    try:
        import angr
        import claripy
    except ImportError:
        print("[symsolve:err] angr 미설치 — SETUP.md 대로 venv 세팅 후 실행:\n"
              "  python3 symsolve.py %s ..." % args.binary, file=sys.stderr)
        return 2

    load_opts = {}
    if args.base is not None:
        load_opts["main_opts"] = {"base_addr": args.base}
    proj = angr.Project(args.binary, auto_load_libs=False, **load_opts)
    print("[symsolve] loaded %s (arch=%s, base=%#x)"
          % (args.binary, proj.arch.name, proj.loader.main_object.min_addr), file=sys.stderr)

    # ── 대칭 입력 심볼 구성 ────────────────────────────────
    symbols = []          # (label, BVS) — 해답 복원용
    state_kwargs = {}
    argv = [args.binary]

    def mk_sym(label, nbytes):
        bv = claripy.BVS(label, nbytes * 8)
        symbols.append((label, bv, nbytes))
        return bv

    if args.arg is not None:
        argv.append(mk_sym("argv1", args.arg))
    if args.file is not None:
        fpath, fn = parse_file_spec(args.file)
        fn = fn or 32
        content = mk_sym("file", fn)
        simfile = angr.SimFile(fpath, content=content, size=fn)
        state_kwargs["fs"] = {fpath: simfile}
    # stdin: --file/--arg 를 안 줬거나 명시했을 때
    if args.stdin is not None or (args.arg is None and args.file is None):
        n = args.stdin if args.stdin is not None else 32
        stdin_sym = mk_sym("stdin", n)
        state_kwargs["stdin"] = stdin_sym

    state = proj.factory.full_init_state(args=argv, **state_kwargs)

    # ── 제약: 문자셋 ──────────────────────────────────────
    charset = None
    if args.charset:
        charset = expand_charset(args.charset)
    elif args.printable:
        charset = list(range(0x20, 0x7f))
    for label, bv, nbytes in symbols:
        for i in range(nbytes):
            byte = bv.get_byte(i)
            if charset is not None:
                state.solver.add(claripy.Or(*[byte == c for c in charset]))
            elif args.no_null:
                state.solver.add(byte != 0)

    # ── 목표 조건 ─────────────────────────────────────────
    find_addrs = [a for a in (parse_addr(x) for x in args.find) if a is not None]
    avoid_addrs = [a for a in (parse_addr(x) for x in args.avoid) if a is not None]
    find_strs = [s.encode() for s in args.find_str]
    avoid_strs = [s.encode() for s in args.avoid_str]

    if not (find_addrs or find_strs):
        print("[symsolve:err] 목표 없음 — --find <ADDR> 또는 --find-str <STR> 필요", file=sys.stderr)
        return 2

    def want(s):
        out = s.posix.dumps(1)
        if find_strs and not any(t in out for t in find_strs):
            return False
        return True  # 주소 조건은 explore(find=)가 처리

    def nope(s):
        out = s.posix.dumps(1)
        return any(t in out for t in avoid_strs)

    find_cond = find_addrs if find_addrs else want
    avoid_cond = avoid_addrs if avoid_addrs else (nope if avoid_strs else None)

    # ── 탐색 ─────────────────────────────────────────────
    simgr = proj.factory.simulation_manager(state)
    print("[symsolve] explore 시작 (find=%s avoid=%s stdin/arg 심볼=%s) ..."
          % (find_addrs or "stdout-str", avoid_addrs or (avoid_strs or "-"),
             ",".join("%s[%d]" % (l, n) for l, _, n in symbols)), file=sys.stderr)
    t0 = time.time()
    explore_kw = {"find": find_cond}
    if avoid_cond is not None:
        explore_kw["avoid"] = avoid_cond
    # find-str 는 주소가 아니므로, 주소 find 와 병용 시 step-callback 로 stdout 도 확인
    if find_addrs and find_strs:
        base_find = find_cond
        explore_kw["find"] = lambda s: (s.addr in base_find) and want(s)

    deadline = t0 + args.timeout
    while True:
        simgr.explore(**explore_kw, n=1)
        if simgr.found or not simgr.active or time.time() > deadline:
            break
    dt = time.time() - t0

    if not simgr.found:
        print("[symsolve] FAIL — 해 없음 (%.1fs, active=%d). 힌트: 입력 길이/문자셋/목표 재확인, "
              "또는 EXTENSION 훅 필요." % (dt, len(simgr.active)))
        return 1

    found = simgr.found[0]
    print("[symsolve] FOUND (%.1fs)" % dt)
    for label, bv, nbytes in symbols:
        val = found.solver.eval(bv, cast_to=bytes)
        print("  %-6s = %r" % (label, val))
        print("  %-6s   hex: %s" % ("", val.hex()))
    stdout = found.posix.dumps(1)
    if stdout:
        print("  stdout: %r" % stdout[:200])

    # concrete-verify: angr 모델 해를 실제 바이너리에 재실행해 대조 (executable oracle).
    if not args.no_verify and (find_strs or avoid_strs):
        ok, detail = concrete_verify(args.binary, symbols, found, find_strs, avoid_strs)
        if ok is None:
            print("  concrete-verify: ⏭  %s" % detail)
        elif ok:
            print("  concrete-verify: ✅ 실제 실행이 목표와 일치 (해 신뢰)")
        else:
            print("  concrete-verify: ⚠️ 불일치 — angr 모델 ≠ 실제(anti-debug/환경/입력모델 의심). "
                  "실제 stdout=%r" % detail)
    return 0


def concrete_verify(binpath, symbols, found, find_strs, avoid_strs):
    """복원 입력을 실제 바이너리에 넣어 재실행 → 목표 문자열 실제 출력 확인.
    h4c.team 실패원인 ⑤(정적/모델 과신) 대응. 반환: (True|False|None, 상세).
    None = 이 호스트에서 실행 불가(교차 아키텍처 등)로 스킵."""
    stdin_val = argv1 = None
    for label, bv, _n in symbols:
        val = found.solver.eval(bv, cast_to=bytes)
        if label == "stdin":
            stdin_val = val
        elif label == "argv1":
            argv1 = val
    # 상대경로면 execvp 가 PATH 검색해 실패 → 절대경로로 고정.
    run_args = [os.path.abspath(binpath)] + ([argv1.decode("latin-1")] if argv1 is not None else [])
    # PE 는 Linux 직접 실행 불가 → wine 있으면 그걸로, 없으면 스킵.
    ftype = subprocess.run(["file", run_args[0]], capture_output=True, text=True).stdout
    if "PE32" in ftype or "MS Windows" in ftype:
        if shutil.which("wine"):
            run_args = ["wine"] + run_args
        else:
            return None, "PE — wine 미설치로 재실행 스킵 (SETUP: apt install wine64)"
    try:
        p = subprocess.run(run_args, input=stdin_val, capture_output=True, timeout=10)
    except Exception as e:
        return None, "재실행 스킵(%s)" % type(e).__name__
    out = (p.stdout or b"") + (p.stderr or b"")
    ok = all(t in out for t in find_strs) and not any(t in out for t in avoid_strs)
    return ok, out[:200]


# ─────────────────────────── selftest (순수 파서, angr 무관) ───────────────────────────
def selftest():
    fails = []

    def chk(c, name):
        print(("  ✅ " if c else "  ❌ ") + name)
        if not c:
            fails.append(name)

    print("== symsolve selftest (순수 파서) ==")
    chk(expand_charset("0-9") == list(range(0x30, 0x3a)), "charset 범위 0-9")
    chk(expand_charset("abc") == [0x61, 0x62, 0x63], "charset 개별문자")
    chk(expand_charset("0-9a-f_") == sorted(set(range(0x30, 0x3a)) | set(range(0x61, 0x67)) | {0x5f}),
        "charset 혼합 범위+문자")
    chk(parse_file_spec("flag.txt:32") == ("flag.txt", 32), "file spec PATH:N")
    chk(parse_file_spec("/a/b.dat") == ("/a/b.dat", None), "file spec N 없음")
    chk(parse_addr("0x401234") == 0x401234 and parse_addr("nope") is None, "addr 파싱")
    print("-" * 40)
    if fails:
        print("FAIL %d: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("ALL GREEN ✅")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="symsolve", description="angr symbolic 하니스")
    p.add_argument("binary", nargs="?")
    p.add_argument("--find", action="append", default=[], metavar="ADDR", help="도달할 주소(반복 가능)")
    p.add_argument("--avoid", action="append", default=[], metavar="ADDR", help="회피 주소(반복)")
    p.add_argument("--find-str", action="append", default=[], metavar="STR", help="stdout 에 뜰 문자열")
    p.add_argument("--avoid-str", action="append", default=[], metavar="STR", help="stdout 회피 문자열")
    p.add_argument("--stdin", type=int, metavar="N", help="심볼릭 stdin N 바이트")
    p.add_argument("--arg", type=int, metavar="N", help="심볼릭 argv[1] N 바이트")
    p.add_argument("--file", metavar="PATH:N", help="심볼릭 파일 입력")
    p.add_argument("--printable", action="store_true", help="입력을 printable ASCII 로 제약")
    p.add_argument("--charset", metavar="SPEC", help="허용 문자셋 (예: '0-9a-f_')")
    p.add_argument("--no-null", action="store_true", help="NUL 바이트 금지")
    p.add_argument("--base", type=lambda s: int(s, 0), metavar="ADDR", help="로드 베이스 재지정")
    p.add_argument("--timeout", type=float, default=120.0, metavar="SEC", help="탐색 상한(기본 120s)")
    p.add_argument("--no-verify", action="store_true", help="복원 해의 실 바이너리 재실행 검증 생략")
    p.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    return p


def main(argv):
    if argv and argv[0] == "selftest":
        return selftest()
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.binary:
        build_parser().print_help()
        return 2
    return solve(args)


# ══════════════════════════════════════════════════════════════════════════════
#  GOTCHAS (실측으로 확인된 함정)
#
#  * scanf("%s") + strlen 기반 검사: angr 의 scanf simprocedure 는 **심볼릭
#    whitespace 종료를 모델링하지 않는다**. 고정길이 심볼릭 stdin 은 항상 그 길이로
#    읽혀 strlen==N 류 검사가 unsat 이 될 수 있다. 대응:
#      - 검사 성공 분기 주소를 --find 로 직접 노림(문자열 대신 주소),
#      - 또는 정확한 입력 길이를 --stdin N 으로 맞춤,
#      - 또는 read()/fgets 로 읽는 지점을 targeting(길이 명확).
#    (read(0,buf,N)+memcmp 형은 0.5s 안에 풀림 — 검증됨.)
#  * full_init_state 가 libc init 때문에 느리면 entry_state 로 교체.
#  * 경로 폭발 시 veritesting=True / LAZY_SOLVES / --avoid 로 조기 가지치기.
#
# ══════════════════════════════════════════════════════════════════════════════
#  EXTENSION 지점 — CLI 로 안 풀리는 경우 여기를 복사·편집한다.
#
#  1) simprocedure 후킹 (예: 커스텀 체크 함수를 상수로 치환):
#       proj.hook_symbol('expensive_hash', MySimProc())
#  2) 특정 함수만 심볼릭 실행 (call_state):
#       st = proj.factory.call_state(0x401234, arg0, prototype='int f(char*)')
#  3) 경로 폭발 억제:
#       add_options={angr.options.LAZY_SOLVES}
#       veritesting=True: proj.factory.simulation_manager(state, veritesting=True)
#  4) 메모리에 심볼릭 버퍼 심기 (stdin/argv 가 아닌 전역):
#       buf = claripy.BVS('buf', 8*N); st.memory.store(addr, buf); st.add_constraints(...)
#  5) 해답 후 재실행 검증 (concrete run) — honest-mode: 심볼릭 해를 실제로 돌려 확인.
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
