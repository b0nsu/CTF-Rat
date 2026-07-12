# ctf-rat — CTF(pwn/rev) 풀이 kit

pwn/rev 집중형 **환경 무관 self-contained CTF 풀이 kit.** 도구 + doctrine + 지식 + 참조데이터가
한 레포에 들어 있어, 어느 Linux 환경(네이티브/VM/WSL2/컨테이너)에든 한 번 세팅하면
Claude·Codex 가 이 레포에서 바로 문제를 푼다.

- **세팅**: [SETUP.md](SETUP.md) (venv+angr+pwntools, Ghidra, glibc-fetch — 한 번)
- **에이전트 진입점/규칙**: [CLAUDE.md](CLAUDE.md) (= `AGENTS.md`, Codex 호환). ROE·6-phase·도구맵.
- **풀이 doctrine**: [doctrine/SOLVING.md](doctrine/SOLVING.md)(ROE+6-phase) · [doctrine/SOLVABILITY.md](doctrine/SOLVABILITY.md) · [doctrine/FINALS.md](doctrine/FINALS.md)
- **지식**: [knowledge/GROUNDING_INDEX.md](knowledge/GROUNDING_INDEX.md) → `knowledge/ctf-skills/`
- **오케스트레이션 청사진**: [RUNNER_ARCHITECTURE.md](RUNNER_ARCHITECTURE.md)

## 레이아웃
```
CLAUDE.md / AGENTS.md      에이전트 진입점 (심볼릭)
SETUP.md                   환경무관 초기 세팅
doctrine/                  SOLVING · SOLVABILITY · calibration · FINALS
knowledge/                 GROUNDING_INDEX + ctf-skills/(pwn) · ctf-reverse/(rev) · ctf-writeup/
reference/                 libc-offsets/ · glibc/(list·SOURCES·glibc-fetch)
bin/                       도구 전체 (+ghidra_scripts/)
solve/_template/rev/       symsolve · vmlift
kernel/                    커널 pwn 확장
tests/                     e2e_mock.py(ctfpull) · e2e_rev.sh(rev 루프)
```

## 핵심 도구
- **`ctfpull`** — CTFd 문제 수집 → `newchal` 스캐폴드. flag 자동제출 안 함(ToS+honest-mode).
  ```sh
  ctfpull ctfd --list [--category pwn]
  ctfpull ctfd --id 42 [--dest DIR]        # 다운로드→해제→ELF판별→run.json→newchal
  ```
  설정: CLI > 환경변수(`CTFD_URL`/`CTFD_TOKEN`) > dotenv(`--env`, 기본 `./.ctfd.env`).
- **`recon <bin>`** — pwn 정적 프로파일 + 보수적 triage.
- **rev 루프** — `revq`(정적 배치: 함수/문자열/xref/interesting/**evasion**) → `decomp`(Ghidra) →
  `symsolve.py`(angr 하니스 + **concrete-verify**) → 커스텀 VM 은 `vmlift.py`.
  ```sh
  revq <bin>                     # 요약 + INTERESTING(check-루틴 후보) + EVASION(anti-debug/packing)
  revq <bin> --func <name>       # 한 함수 이웃 카드(디컴파일 전 컨텍스트 절약)
  symsolve.py <bin> --find-str Correct --stdin 16 --printable   # 복원 후 실 바이너리 재실행 검증
  vmlift.py --disasm|--run|--solve [blob]
  ```
  revq 주소 = angr 로드베이스(PIE 0x400000) → `symsolve --find <주소>` 그대로 투입.
- **pwn**: `pwnkit`/`pwnstage`/`primitives` · **버스**: `state`(확정/배제/다음 기록) · **커널**: `k_*`(kernel/).

## 테스트 (도구 수정 후 회귀검증)
```sh
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 bin/ctfpull selftest && python3 tests/e2e_mock.py
bash tests/e2e_rev.sh        # angr 있으면 실 crackme e2e, 없으면 selftest 만
```
전부 `ALL GREEN ✅`이면 통과.

## 설계 원칙 (RUNNER_ARCHITECTURE.md)
한 번에 활성 문제 1개 · 팬아웃은 문제 "안"에서만 · 큰 읽기는 서브에이전트로 위임하고 결론만 회수 ·
STATE.jsonl 단일 진실원 · 재발명 금지(기존 도구 재사용).
