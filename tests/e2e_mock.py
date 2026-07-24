#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ctfpull e2e 테스트 — 로컬 mock CTFd 서버로 네트워크 경로 전체 검증.
목록→상세→첨부 다운로드→(zip)해제→ELF 판별→run.json→newchal 명령 생성까지.
라이브 대회 없이 CI/회귀검증 가능. 실행: python3 tests/e2e_mock.py
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CTFPULL = os.path.join(HERE, "..", "bin", "ctfpull")
FAKE_ELF = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56  # 판별용 최소 ELF 헤더


def make_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("chal", FAKE_ELF)
        z.writestr("libc.so.6", FAKE_ELF)
        z.writestr("ld-linux-x86-64.so.2", FAKE_ELF)
        z.writestr("Dockerfile", b"FROM ubuntu:22.04\n")
    return buf.getvalue()


ZIP = make_zip()

CHALLENGES = [
    {"id": 1, "name": "warmup pwn", "category": "pwn", "value": 100, "solves": 12},
    {"id": 2, "name": "baby rev", "category": "rev", "value": 150, "solves": 8},
]
DETAIL_1 = {
    "id": 1, "name": "warmup pwn", "category": "pwn", "value": 100,
    "connection_info": "<a href='#'>nc pwn.demo.io 31337</a>",
    "files": ["/files/deadbeef/handout.zip?token=xyz"],
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        body = json.dumps({"success": True, "data": obj}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        # 인증 헤더 존재 확인 (토큰 경로 검증)
        if self.headers.get("Authorization") != "Token TESTTOKEN":
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"success": false, "errors": "no auth"}')
            return
        if path == "/api/v1/challenges":
            self._json(CHALLENGES)
        elif path == "/api/v1/challenges/1":
            self._json(DETAIL_1)
        elif path.startswith("/files/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(ZIP)))
            self.end_headers()
            self.wfile.write(ZIP)
        else:
            self.send_response(404)
            self.end_headers()


def run_ctfpull(port, *args):
    base = "http://127.0.0.1:%d" % port
    cmd = [sys.executable, CTFPULL, "ctfd", "--url", base, "--token", "TESTTOKEN"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    ok = True

    def check(label, cond, extra=""):
        nonlocal ok
        ok = ok and cond
        print(("  PASS " if cond else "  FAIL ") + label + (("  " + extra) if extra and not cond else ""))

    print("[e2e] --list")
    r = run_ctfpull(port, "--list")
    check("exit 0", r.returncode == 0, r.stderr)
    check("pwn 문제 표시", "warmup pwn" in r.stdout, r.stdout)
    check("총 2개", "총 2개" in r.stdout, r.stdout)

    print("[e2e] --list --category pwn")
    r = run_ctfpull(port, "--list", "--category", "pwn")
    check("rev 제외", "baby rev" not in r.stdout, r.stdout)
    check("총 1개", "총 1개" in r.stdout, r.stdout)

    print("[e2e] --id 1 --no-newchal (다운로드→해제→판별→manifest)")
    with tempfile.TemporaryDirectory() as tmp:
        r = run_ctfpull(port, "--id", "1", "--no-newchal", "--dest", tmp)
        check("exit 0", r.returncode == 0, r.stderr)
        stage = os.path.join(tmp, "warmup_pwn")
        check("스테이징 디렉토리 생성", os.path.isdir(stage))
        check("zip 다운로드", os.path.isfile(os.path.join(stage, "handout.zip")))
        check("zip 해제(chal)", os.path.isfile(os.path.join(stage, "chal")))
        rj = os.path.join(stage, "run.json")
        check("run.json 생성", os.path.isfile(rj))
        if os.path.isfile(rj):
            m = json.load(open(rj))
            check("connection_info 파싱", m.get("connection_info") == "pwn.demo.io:31337", str(m.get("connection_info")))
            check("main_bin=chal", m.get("detected", {}).get("main_bin") == "chal", str(m.get("detected")))
            check("libc 판별", m.get("detected", {}).get("libc") == "libc.so.6", str(m.get("detected")))
            check("ld 판별", m.get("detected", {}).get("ld") == "ld-linux-x86-64.so.2", str(m.get("detected")))
            check("Dockerfile 판별", m.get("detected", {}).get("dockerfiles") == ["Dockerfile"], str(m.get("detected")))
            check("flag=None", m.get("flag") is None)
            check("file sha256 기록", m["files"] and "sha256" in m["files"][0])
            check("rat.run/v1 manifest", m.get("schema") == "rat.run/v1", str(m.get("schema")))
            check("manifest input provenance", all(x.get("sha256", "").startswith("sha256:") and isinstance(x.get("size"), int)
                                                   for x in m.get("inputs", [])), str(m.get("inputs")))
        check("newchal 명령 출력", "newchal warmup_pwn" in r.stdout and "pwn.demo.io:31337" in r.stdout, r.stdout)

    print("[e2e] --no-extract")
    with tempfile.TemporaryDirectory() as tmp:
        r = run_ctfpull(port, "--id", "1", "--no-newchal", "--no-extract", "--dest", tmp)
        stage = os.path.join(tmp, "warmup_pwn")
        check("no-extract exit 0", r.returncode == 0, r.stderr)
        check("archive 유지", os.path.isfile(os.path.join(stage, "handout.zip")))
        check("archive 내용 미해제", not os.path.exists(os.path.join(stage, "chal")))

    print("[e2e] 인증 실패 경로 (토큰 누락)")
    base = "http://127.0.0.1:%d" % port
    r = subprocess.run([sys.executable, CTFPULL, "ctfd", "--url", base, "--list"],
                       capture_output=True, text=True)
    check("403 → 비정상 종료", r.returncode != 0, r.stderr)
    check("에러 메시지에 HTTP", "HTTP 403" in r.stderr, r.stderr)

    srv.shutdown()
    print("\n[e2e] " + ("ALL GREEN ✅" if ok else "FAILED ❌"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
