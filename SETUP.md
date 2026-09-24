# SETUP — 어느 환경에서든 ctf-rat 준비 (한 곳에 한 번)

`ctf-rat` = **환경 무관 self-contained CTF(pwn/rev) 풀이 kit.** Linux(네이티브 / VM /
WSL2 / 컨테이너) 어디든 한 번 세팅하면, Claude·Codex 가 이 레포에서 바로 풀이를 수행한다.
(예전 "Mac→WSL SSH 배포" 방식은 폐기 — 이제 클론한 그 자리에서 돈다.)

> 도구는 **`CTF_HOME`(레포 루트)을 스스로 해석**한다. 경로 설정 없이 `bin/` 만 PATH 에 넣으면 됨.

---

## 0. 전제
- Linux x86-64 (또는 WSL2 / VM / Docker). Python **3.12 권장**. `git`, `curl`.
- amd64 기준. i386/기타 아키는 해당 패키지 추가 필요.

## 1. 클론 + PATH
```bash
git clone https://github.com/b0nsu/CTF-Rat && cd CTF-Rat
export PATH="$PWD/bin:$PATH"          # k_* 커널 래퍼 포함 전 도구
export PYTHONPATH="$PWD/bin${PYTHONPATH:+:$PYTHONPATH}"  # exploit.py의 pwnkit/pwnstage import
# (선택) export CTF_HOME="$PWD"       # 안 해도 도구가 레포루트 자동 해석
```

## 2. Python 환경 (pwn과 native angr 분리)
```bash
# pwn 도구용 환경
python3.12 -m venv .venv && . .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt ropgadget
#   pwntools → recon/pwnkit/pwnstage

# native Unicorn이 필요한 rev 심볼릭 실행용 환경
deactivate
.venv/bin/python -m venv .venv-angr
.venv-angr/bin/python -m pip install --upgrade pip
.venv-angr/bin/python -m pip install -r requirements-angr.txt
.venv-angr/bin/python -c "import angr; from angr.engines import UberEnginePcode; assert angr.engines.unicorn._UC_NATIVE is not None"
```

`bin/symsolve`, 기본 `revq`, rev 분석을 수행하는 `rat` 명령, `rat-slice`와 `rat-qiling`은
`.venv-angr/bin/python`을 자동 선택한다. 다른 native-angr 환경은
`RAT_ANGR_PYTHON=/path/to/python`으로 지정할 수 있다. wrapper로 실행하지 않고 다른
인터프리터에서 직접 `symsolve.py`를 실행하면 그 인터프리터 자체가 native Unicorn 검증을
통과해야 한다. 환경이 없거나 `_UC_NATIVE`가 비활성이면 exit 2와 이 설정 안내를 출력한다.

angr 9.2.223의 native bridge에는 `unicorn==2.1.4`가 필요하다. pwntools 4.15는 이 버전을
제외하므로 두 패키지 집합을 분리했다. `.venv`는 pwn 도구에, `.venv-angr`는 rev 심볼릭
실행에 쓴다.

### 선택적 deep 이미지 (CI/이식 런타임)
```bash
RAT_DEEP_IMAGE="${RAT_DEEP_IMAGE:-ctf-rat:deep}"
docker build --platform=linux/amd64 -f Dockerfile.test -t "$RAT_DEEP_IMAGE" .
#   이미지의 기본 Python에는 pwntools, /opt/ctf-rat-angr에는 native angr를 각각 설치한다.
#   requirements-deep.txt는 분리된 angr 환경 전용이다.
# 자동 dispatch나 ratbench의 자동 빌드는 없다. 사람이 명시해 컨테이너에서 실행할 때만 사용한다.
docker run --rm --network none -v "$PWD:$PWD" -w "$PWD" -e CTF_HOME="$PWD" \
  "$RAT_DEEP_IMAGE" bin/symsolve ./challenge --find-str Correct --stdin 16
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
- 챌린지가 `Dockerfile` 을 주면 [DOCKER.md](DOCKER.md) 를 우선 사용해 이미지에서 정확한
  `libc.so.6`/`ld-linux` 를 추출하고 loopback 서비스로 검증한다.

## 6. 검증 (전부 `ALL GREEN` 이어야 함)
```bash
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 bin/ctfpull selftest
```
angr 미설치 환경이면 revq 는 `selftest`·`--fast`(binutils) 만, symsolve 는 `selftest` 만 동작.

## 7. 사용 (진입점)
- **터미널 표지·시작 점검**: 1절처럼 레포 `bin/`을 PATH 맨 앞에 두면, 이 레포 안에서 인자 없이 대화형으로 `claude` 또는 `codex`를 열 때 마스코트 표지와 빠른 환경 점검을 보여준다. 검사 중에는 경과 시간이 갱신되고, 결과에는 각 항목과 전체 소요 시간이 표시된다. Python 3.10+, `file`, `objdump`, `.venv`의 pwntools, `.venv-angr`의 native Unicorn은 필수이며, GDB와 Ghidra(`analyzeHeadless` + Java)는 설치 여부를 확인해 누락 시 안내한다. 필수 항목이 실패하면 `SETUP.md` 경로를 보여주고 중단한다. 레포 밖이나 비대화형 명령에는 표지·점검이 없다. 색을 끄려면 `NO_COLOR=1`을 사용한다. 전체 도구 회귀 검증은 별도로 `pkselftest`를 실행한다.
- **풀이 진입**: 레포 루트에서 `claude`(또는 codex) → `CLAUDE.md` 자동 로드(풀이 doctrine 진입점).
- **수집/스캐폴드**: `ctfpull ctfd --id N` → `solve/<name>/artifact/`에 원본 수집 → `newchal <name> <bin> [libc] [host:port]`
- **rev**: `revq <bin>` → `revq <bin> --func <후보>` → `decomp <bin> <fn>` → `symsolve … --find-str …`
- **pwn**: `recon <bin>` → `decomp` → `pwnkit`/`pwnstage` → `state` 로 진행 기록
- **주소 계산**: `pwncalc elf-offset --elf ./libc.so.6 --symbol puts` →
  `pwncalc relocate --elf ./libc.so.6 --leak 0x... --leak-symbol puts --symbol system --string /bin/sh`
- **범위 검사**: `pwnscope ./solve.py` 로 로컬/원격 transport와 같은 디렉토리의 `run.json` 단일 endpoint 일치 확인
- **입력·체인 검증**: `pwnleak --text '0x...'` (`ARM32 kernel`이면 `--bits 32 --arch arm`) → `pwncalc ...` → `pwnropcheck --file chain.json --map ./libc.so.6@0x...` →
  `pwnpayload --file payload.bin --consumer read --bad-byte newline`
- **로컬 크래시 증거**: `pwncrash ./chall --pattern-length 256` (일반 실행 재현과 GDB core를 기록하지만 primitive PASS는 수동 검토 후 기록)
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
- 분리 환경에서는 `.venv-angr/bin/python solve/_template/rev/qiling_trace.py <pe> --rootfs <dir>`로 실행한다.
- 라우팅은 `knowledge/GROUNDING_INDEX.md`(PE/.NET 행), rev 지식은 `knowledge/ctf-reverse/`.
