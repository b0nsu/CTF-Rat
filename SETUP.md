# SETUP — 어느 환경에서든 ctf-rat 준비 (한 곳에 한 번)

`ctf-rat` = **환경 무관 self-contained CTF(pwn/rev) 풀이 kit.** Linux(네이티브 / VM /
WSL2 / 컨테이너) 어디든 한 번 세팅하면, Claude·Codex 가 이 레포에서 바로 풀이를 수행한다.
(예전 "Mac→WSL SSH 배포" 방식은 폐기 — 이제 클론한 그 자리에서 돈다.)

> 도구는 **`CTF_HOME`(레포 루트)을 스스로 해석**한다. 경로 설정 없이 `bin/` 만 PATH 에 넣으면 됨.

---

## 0. 전제
- Linux x86-64 (또는 WSL2 / VM / Docker). Python **3.10+**. `git`, `curl`.
- amd64 기준. i386/기타 아키는 해당 패키지 추가 필요.

## 1. 클론 + PATH
```bash
git clone https://github.com/b0nsu/CTF-Rat && cd CTF-Rat
export PATH="$PWD/bin:$PATH"          # k_* 커널 래퍼 포함 전 도구
# (선택) export CTF_HOME="$PWD"       # 안 해도 도구가 레포루트 자동 해석
```

## 2. Python 환경 (angr / pwntools — rev·pwn 핵심)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install --upgrade pip
pip install angr pwntools ropgadget
#   angr → claripy/cle/pyvex 동반 (revq deep 추출·symsolve symbolic)
#   pwntools → recon/pwnkit/pwnstage
```

## 3. 시스템 도구
```bash
# Debian/Ubuntu 예시 (배포판에 맞게)
sudo apt install -y gdb build-essential file binutils patchelf xxd
# 강력 추천 (선택)
sudo apt install -y ruby && sudo gem install one_gadget seccomp-tools
# pwninit (libc 자동 patchelf) — rust 있으면
cargo install pwninit    # 또는 GitHub 릴리스 바이너리
```

## 4. Ghidra (decomp 용 — 권장)
```bash
# https://github.com/NationalSecurityAgency/ghidra/releases 에서 받아 해제 후:
export GHIDRA_HOME=/opt/ghidra_11.x_PUBLIC
```
- `decomp <bin>` 는 `GHIDRA_HOME` 없으면 `/opt/ghidra_11.2.1_PUBLIC` 기본값을 시도한다.
- Ghidra 없이도 `revq`(angr)·`objdump`/`nm` 로 상당 부분 커버 가능.

## 5. glibc DB (pwn 문제 만나면 그때만 — **축적하지 않음**)
```bash
reference/glibc/glibc-fetch 2.35-0ubuntu3 amd64    # 필요한 버전만 로컬로 내려받음
```
- 카탈로그: `reference/glibc/list` · 다운로드 출처: `reference/glibc/SOURCES.md`
- 받은 libs 는 `reference/glibc/libs/` (gitignore — 커밋 안 됨)
- 최신 계열: 2.41(Ubuntu 25.10) / 2.40(24.10) / 2.39(24.04) / 2.35(22.04)

## 6. 검증 (전부 `ALL GREEN` 이어야 함)
```bash
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 bin/ctfpull selftest
```
angr 미설치 환경이면 revq 는 `selftest`·`--fast`(binutils) 만, symsolve 는 `selftest` 만 동작.

## 7. 사용 (진입점)
- **풀이 진입**: 레포 루트에서 `claude`(또는 codex) → `CLAUDE.md` 자동 로드(풀이 doctrine 진입점).
- **수집/스캐폴드**: `ctfpull ctfd --id N` → `newchal <name> <bin> [libc] [host:port]`
- **rev**: `revq <bin>` → `revq <bin> --func <후보>` → `decomp <bin> <fn>` → `symsolve … --find-str …`
- **pwn**: `recon <bin>` → `decomp` → `pwnkit`/`pwnstage` → `state` 로 진행 기록
- **doctrine**: `doctrine/SOLVING.md`(ROE+6-phase), `doctrine/SOLVABILITY.md`, `knowledge/GROUNDING_INDEX.md`

## 8. Windows rev (PE/DLL/.NET) — 옵션 (Windows 문제 만나면만)
정적 분석은 **Ghidra(`decomp`) + angr(`revq`)** 로 Linux 에서 그대로 된다(revq 가 PE 감지 시 라우팅 배너 출력).
동적/실행은 아래 (Linux 호스트에서, Wine 불필요):
```bash
pip install qiling frida-tools        # Qiling PE 에뮬(Wine 불필요) + Frida 계측
sudo apt install -y wine64            # .exe 직접 실행/재현 (symsolve concrete-verify 가 PE면 자동 wine)
# .NET / Unity
dotnet tool install -g ilspycmd       # ILSpy CLI (.NET 디컴파일)  |  IL2CPP=il2cppdumper, Mono=monodis
```
- **동적 정석 = `solve/_template/rev/qiling_trace.py`**(Qiling 에뮬, Wine 불필요). Windows **rootfs**(DLL) 필요 — 파일 상단 참고.
- 라우팅은 `knowledge/GROUNDING_INDEX.md`(PE/.NET 행), rev 지식은 `knowledge/ctf-reverse/`.
