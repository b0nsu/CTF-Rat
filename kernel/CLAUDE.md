# Kernel pwn 작업 규칙 (이 디렉토리 = kernel/, Claude Code 구동)

> userland 규칙(`doctrine/SOLVING.md`)의 **커널 확장**. 같은 철학(context 안 터뜨림 · raw 명령 대신 래퍼 · 큰 상태는 파일로) · 다른 기질(QEMU+initramfs+.ko+KASLR/SMEP/SMAP/KPTI).
> **판정은 아래 "SOLVABILITY (kernel)" 절 참조. 답/writeup/flag 검색 금지, 오프셋은 전부 live 실측.**

## 미션
Linux kernel exploitation. 목표: 정적분석으로 취약점·완화 파악 → exploit.c 작성 → initramfs 재패킹 → QEMU 부팅+gdb 관찰 루프를 **최소 round-trip**으로 돌려 root 셸(또는 flag) 획득.

## 셋업 (진입 즉시)
```bash
export PATH="$(git rev-parse --show-toplevel)/bin:$PATH"   # k_* 커널 래퍼 포함 (userland 도구와 동거)
```
- 작업은 챌린지 디렉토리(또는 `kernel/`)에서. 커널 도구(k_run_qemu/k_repack/k_dump_heap/k_kallsyms)는 CTF_HOME 자동 해석.
- 환경 준비(QEMU·gdb·pwntools 등)는 레포 루트 `SETUP.md` 참조.

## 4-페이즈 고정 루프 (rabbit-hole 방지 — 순서 지킬 것)

### Phase 1 — 정적분석 / 완화 파악
1. init 스크립트(`init`,`/etc/init.d/*`)·제공 `run.sh`·`.ko` 모듈 확인. **완화 확정**: KASLR / SMEP / SMAP / KPTI / `kptr_restrict` / `dmesg_restrict` / seccomp.
   - `run.sh` 있으면 그 QEMU 라인의 `-cpu`,`-append`,`-m`,`-smp` **그대로 미러** (재발명 금지). `run_qemu.sh` 는 cwd의 run.sh 감지 시 그 라인을 stderr로 보여줌.
2. 심볼·베이스: `vmlinux` 있으면 `nm`, 없으면 `System.map`/`/proc/kallsyms`. **KASLR base·심볼 오프셋은 `kallsyms_diff.py` 로 live 실측**(recall 금지).

### Phase 2 — 페이로드 작성 + 재패킹 (자동)
3. `exploit.c`(정적, `-static`) 작성/수정. 커널 타깃 primitive 골격.
4. `repack.sh -i <initramfs> -e exploit.c` → static 컴파일 → initramfs cpio 트리에 주입 → 원본 압축 방식대로 재패킹. 출력 이미지 경로를 stdout으로 반환.

### Phase 3 — 가벼운 디버깅 + 트리거
5. `run_qemu.sh -k <bzImage> -i <repacked>` → gdbstub(:1234) 열고 백그라운드 부팅, 콘솔은 `qemu.log`로. (`-S` 옵션 = boot에서 halt, early attach용. `--debug` = nokaslr+earlyprintk.)
6. gdb 붙여 vuln 지점 BP, **바뀐 레지스터(`$rip`,`$rsp`)·타깃 struct만 핀포인트** 관찰. 전체 context 덤프 금지.
   - `gdb -q -x kernel/.gdbinit-kernel` → `kattach`(=target remote :1234). pagination/color off, context=regs+disasm+code.
7. **큰 상태(레지스터셋·메모리·slab)는 `dump_heap.py` 로 파일로** 빼고 `grep`/`awk`. 인라인 덤프 금지.

### Phase 4 — 크래시 분석 피드백
8. panic/oops 시 `qemu.log`의 레지스터·call trace로 결함 파악 (`-no-reboot`라 panic에서 정지).
9. Phase 2로 복귀·수정, root 셸까지 루프. **stop-loss(L4)** 준수.

## 도구 (전부 kernel/bin, PATH 추가 또는 bin/k_* 심볼릭)
| 목적 | 명령 |
|---|---|
| QEMU 부팅(gdbstub+백그라운드+콘솔→파일) | `run_qemu.sh -k bzImage -i initramfs [--debug] [-S] [-p PORT]` |
| initramfs 재패킹(컴파일+주입) | `repack.sh -i initramfs.cpio.gz -e exploit.c [--name N --dest /path]` |
| 큰 커널 상태 → 파일 (batch gdb) | `dump_heap.py --regs` / `--addr 0x.. --len N` / `--vmlinux vmlinux --sym NAME` / `--cmd "x/40gx \$rsp"` |
| KASLR base·심볼 오프셋 live 해석 | `kallsyms_diff.py System.map --base 0x.. ` / `--anchor sym=0x.. [--sym A B] [--all]` |
| gdb 튜닝(색/페이지/context off) | `gdb -q -x kernel/.gdbinit-kernel` 후 `kattach` |

## 지식 계층 (grounding — driver 아님, userland 승계)
- 기법 카탈로그: `knowledge/ctf-skills/kernel.md`, `kernel-techniques.md`, `kernel-bypass.md` (vendored). **라우터=`knowledge/GROUNDING_INDEX.md`** — "커널(KASLR/SMEP/SMAP/ret2usr/cred/modprobe)" 행에서 특정 후 해당 파일만 열 것(통째 로드 금지).
- 특히 `modprobe_path`가 `CONFIG_STATIC_USERMODEHELPER`로 막힌 경우(→ `call_usermodehelper_setup`이 요청 경로 대신 컴파일된 `static_usermodehelper_path`(예: `/sbin/usermode-helper`, 보통 rootfs에 없음)를 실행): **`core_pattern`도 같은 `call_usermodehelper` 병목을 타므로 똑같이 막힌다 — 대안 아님.** 실전 확인 사례: kaleido 챌린지에서 modprobe_path leak/overwrite(readback까지)는 완벽했으나 helper가 전혀 안 떴고, 원인이 STATIC_USERMODEHELPER였음. 이때 정석은 **cred 데이터 직접 조작(data-only)**: arbitrary R/W로 `init_task`(kbase-relative) 순회→`getpid()` 매칭 task_struct 찾기→`task->cred`(commit_creds 디스어셈블로 확인: `real_cred=+0x590`,`cred=+0x598`) 포인터의 cred 구조체 uid/gid/…/fsgid(cred+0x4~+0x20) 전부 0으로. RIP 제어가 되면 `commit_creds(prepare_kernel_cred(0))`도 가능. (오프셋은 전부 이 커널에서 live 재확인.) `kernel.md`의 core_pattern 절은 STATIC_USERMODEHELPER **비활성**일 때만 유효.
- 오프셋/gadget/주소는 여기서 recall 금지 — 문서는 개념 예시일 뿐, 전부 이 바이너리·이 커널에서 live 실측 후 사용.

## context 규율 (userland과 동일 철학)
- **큰 출력은 항상 파일로**: 콘솔은 `qemu.log`, gdb 대량 상태는 `dump_heap.py` → `dumps/`. raw `gdb`/전체 `x/`/`info all-registers` 인라인 금지.
- gdb는 **batch·핀포인트**: 필요한 레지스터/주소만. pwndbg 전체 배너/context 패널은 `.gdbinit-kernel` 이 이미 억제.
- ANSI/배너 잔여물은 userland `pwnclean` 필터 재사용 가능(`... | pwnclean`).
- 주소/offset/gadget/slide는 **STATE.jsonl 버스에 기록 후 사용**(hallucinate 방지). 진입 즉시 `state show`, checkpoint마다 append (`state offset`/`ok`/`no`/`next`/`alert`). userland CLAUDE.md의 데이터-버스 규약 그대로.

## 커널 디버깅 모델 (gdbq 한계 정정과 대응)
- QEMU gdbstub는 **halt(-S)·BP 정지 상태의 메모리/레지스터 관찰**에 강함 → `dump_heap.py`(batch)·`.gdbinit-kernel`이 이 용도.
- 반면 **트리거(입력 드라이브)는 gdb stdin이 아니라 guest 안 exploit**이 함: initramfs의 `init`이 자동 실행하거나, 인터랙티브가 필요하면 `run_qemu.sh --fg`(serial 상호작용).
- 즉: gdb=관찰자, exploit(guest 내부)=구동자. userland의 "gdbq는 메뉴 구동 못 함, 구동은 pwntools"와 같은 분업.

## 파이프라인 self-test (testkit/)
`kernel/testkit/` = distro 커널(bzImage, linux-image-kvm) + 정적 init.c + exploit.c + base.cpio.gz. 도구 변경 후 회귀검증:
```bash
cd kernel/testkit
OUT=$(repack.sh -i base.cpio.gz -e exploit.c --name exploit)
run_qemu.sh -k bzImage -i "$OUT" --debug
grep -aE 'SMOKE_INIT_OK|PWN_EXPLOIT_RAN' qemu.log   # 둘 다 나오면 repack+boot 파이프라인 정상
```
(실제 커널 챌린지가 아니라 **인프라 검증용**. 진짜 exploit 개발은 실제 챌린지 확보 후.)

## honest-mode (오염 금지 — userland SOLVABILITY 그대로 + 커널 강조)
- ✅ 허용: 기법/개념 검색 (KASLR bypass 이론, kernel ROP/JOP, `modprobe_path`/`cred` overwrite, ret2usr, `commit_creds(prepare_kernel_cred(0))` 원리, CVE 클래스 일반론).
- ❌ 금지: **이 챌린지의** 답/writeup/exploit/flag 검색.
- KASLR slide·심볼 주소·struct 필드 오프셋은 커널 버전마다 드리프트 → **전부 live 실측**(`/proc/kallsyms`·leak·gdb). recall한 상수는 반드시 재확인. (userland `calibration.md`의 recall-오탐 사례와 동형.)

## SOLVABILITY (kernel) — L0 하드스킵 amend
- `doctrine/SOLVABILITY.md` L0는 mixed 파일 더미 triage에서 kernel을 즉시 후순위로 둠. **그 규칙은 "커널이 명시적 목표"인 지금엔 적용 안 됨** — 이 환경이 구축됐으므로 kernel은 더 이상 자동 스킵이 아니다. (그 문서 L0에 이 파일로의 cross-ref 추가함.)
- L1(정적 prior)·L3(체인 완성도)·L4(stop-loss 예산)는 그대로 승계. L2(primitive 게이트)만 커널 shape로 치환:
  - userland "제어된 heap write / libc leak / one_gadget" ↔ **kernel "제어된 커널 오브젝트 write / KASLR-slid 주소 leak / SMEP·SMAP 우회 gadget(또는 ret2usr 성립)"**.
  - "될 것 같다"(정적)는 확신 아님 — **로컬(QEMU)에서 primitive 실증**해야 SOLVE 상승.
- verdict 공식·정밀도 우선(보수적 분류) 원칙 동일.

## 핸드오프 (세션 종료/인계 시 — userland "팀 공유물" 절의 커널 대응)
- 진행 상황을 HANDOFF.md(또는 메모리)에 "완료/성공"으로 적기 전, **그 근거가 된 가장 최근 qemu.log를 다시 열어 실제 결과를 재확인**할 것. 크래시(panic/oops)나 부팅 실패 로그를 성공으로 오인해 기록하지 말 것.
- "성공 flag" 문자열이 실제 챌린지 flag(원본 그대로 제공된 경로/디스크)에서 나온 것인지, 디버그용으로 직접 심어둔 테스트 문자열인지 반드시 구분해서 기록.
- **HANDOFF 작성 직전 `state show`로 최종 대조**: 이번 세션에서 언급됐던 계획-무효화급(alert) 발견이
  전부 STATE.jsonl에 실제로 들어갔는지 확인. 채팅/HANDOFF 프로즈에만 있고 STATE엔 없는 발견이 있으면
  그때라도 기록 — "발견 즉시" 규칙이 뚫렸어도 여기서 한 번 더 걸러지는 최후 안전망.
- 다음 세션이 이어받을 수 있게 HANDOFF.md에: 확정 오프셋(kbase-relative)·검증된 primitive·막힌 기법과 이유·다음 시도 후보를 남길 것. 같은 챌린지를 다른 세션이 재검증할 경우 **오염 여부(이전 결과 재사용 가능한지, 재현 안 되는지)를 발견 즉시 사용자에게 보고**.

## GDB MCP (spec 해결방안 #2) — 평가 결과: 연기
- compact-text 경로(`.gdbinit-kernel` + batch `dump_heap.py` + pwnclean)가 **검증 완료·주력**. spec #2("구조화 데이터 추출")의 의도를 이미 충족.
- 즉시 쓸 pip GDB-MCP 패키지 없음. node/npx(=/mnt/c nodejs) 경유 설치는 가능하나 **외부 MCP 연결은 사용자 승인 필요한 결정**(신규 외부 의존+신뢰). → **선택적 future work**. 붙일 때도 compact-text를 fallback으로 유지(블로킹 의존 금지).
