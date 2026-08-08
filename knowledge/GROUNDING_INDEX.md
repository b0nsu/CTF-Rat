# Grounding Index — 유형(vuln class) → 지식소스 매핑

> **목적**: triage에서 분석 class를 확정한 뒤, 로컬 artifact 분석에 필요한 *하나의 파일*만 grounding으로 선택하는 라우터.
> 지식은 **grounding**(개념 확인)이지 **driver**(풀이 대행) 아님. 확신은 SOLVABILITY.md 게이트대로
> **이 바이너리에서 fresh 도출 + 로컬 실증**했을 때만. 답/writeup 검색 금지.

## 사용 규율 (context 규율 = CLAUDE.md 승계)
1. **통째 로드 금지.** pwn=`knowledge/ctf-skills/*.md`(~9000줄), rev=`knowledge/ctf-reverse/*.md`(~9400줄). triage로 확정된 **1개 파일만**.
2. **큰 읽기는 subagent(Task)에 위임** → 결론(관련 기법명·전제·완화조건·코드 스니펫)만 회수. 메인 컨텍스트에 원문 붙이지 말 것.
3. 각 파일 첫머리에 **Table of Contents** 있음 → 먼저 ToC만 grep(`grep -m30 '^##' <file>`)해 섹션 특정 후, 그 섹션만 발췌.
4. **오프셋/gadget/상수는 여기서 recall 금지** — 전부 바이너리·gdb 실측 후 `state offset`. 문서 값은 개념 예시일 뿐.
5. glibc 게이팅은 **how2heap(버전태그) 우선**, ctf-skills는 폭 보강.
6. 이 라우터는 외부 상호작용·결과 획득을 위한 실행 지침을 자동으로 불러오지 않는다. 고위험 실행·격리 경계·kernel 자료는 기본 경로에서 제외한다.

## 소스 3축
| 소스 | 경로 | 강점 |
|---|---|---|
| ctf-skills (=ctf-pwn) | `knowledge/ctf-skills/` (vendored, MIT) | **pwn**의 로컬 메모리 안전성·allocator 개념 참고 |
| ctf-reverse | `knowledge/ctf-reverse/` (vendored, MIT) | **rev**: anti-analysis·언어별(Go/Rust/.NET…)·RE 패턴·VM·툴(Ghidra/angr/frida/qemu) |
| ctf-writeup | `knowledge/ctf-writeup/SKILL.md` (vendored, MIT) | writeup 작성 표준(제출형식·체크리스트) — 참고용 |
| how2heap | 외부: github.com/shellphish/how2heap (선택 clone) | glibc 버전별 heap 정밀(safe-linking/hook/tcache 게이팅) |
| kernel env | `kernel/` + `ctf-skills/kernel*.md` | 커널 (환경이 상위, md는 개념 참조) |

## triage class → 파일 라우팅
| vuln class (triage) | 1차 grounding | 보조 |
|---|---|---|
| stack overflow / 제어흐름 손상 | `ctf-skills/overflow-basics.md`의 개념·완화조건 절 | — |
| leak 또는 제어흐름 재구성 | 바이너리의 로컬 RE 및 `overflow-basics.md` | — |
| stack pivot / SROP / 고급 제어흐름 기법 | 기본 라우팅 제외 | — |
| format string (GOT/fmt leak/%n) | `ctf-skills/format-string.md` | — |
| heap glibc (tcache/fastbin/UAF/overlap/House of *) | **how2heap(버전 확정 후)** | `ctf-skills/heap-techniques.md`, `heap-techniques-2.md` |
| FSOP / _IO_FILE / House of Apple2 / vtable | `ctf-skills/heap-fsop.md` | `heap-techniques.md`(Apple2 절) |
| non-glibc heap (musl / nginx pool / talloc) | `ctf-skills/heap-techniques-2.md` | — |
| seccomp / 격리 경계 | 기본 라우팅 제외; 로컬 정책 분석과 차단 원인만 기록 | — |
| custom VM / bytecode interpreter | `ctf-reverse/patterns-runtime.md` | 본체는 바이너리 RE |
| kernel | 기본 라우팅 제외 | — |
| 잡다한 실전 팁 / 디버깅 관용구 | `ctf-skills/field-notes.md` | — |
| 위에 안 잡히는 복합 동작 | 기본 라우팅 제외; 로컬 RE 사실을 먼저 축적 | — |

## rev challenge → 파일 라우팅 (`knowledge/ctf-reverse/`)
> rev 본체는 바이너리 RE(우리 도구 `revq`→`decomp`→`symsolve`/`vmlift`). 아래는 개념 grounding.
| rev 상황 | 1차 grounding | 보조 |
|---|---|---|
| 시작점 / 전반 라우팅 | `ctf-reverse/SKILL.md`(ToC) | `patterns.md` |
| crackme / keygen / serial 검증 로직 | `ctf-reverse/patterns-ctf.md` | `patterns-ctf-2.md`, `patterns-ctf-3.md` |
| anti-debug / packing / 난독화 (revq **EVASION** 뜨면) | `ctf-reverse/anti-analysis-ctf.md` | `anti-analysis.md` |
| 언어별(Go/Rust/C++/.NET/Nim…) | `ctf-reverse/languages.md` | `languages-compiled.md`, `languages-platforms.md` |
| custom VM / bytecode (→ `vmlift`) | `ctf-reverse/patterns-runtime.md` | — |
| 툴 선택(Ghidra/IDA/angr/frida/qemu) | `ctf-reverse/tools.md` | `tools-dynamic.md`, `tools-emulation.md`, `tools-advanced{,-2}.md` |
| 플랫폼(모바일/임베디드/HW) | `ctf-reverse/platforms.md` | `platforms-hardware.md` |
| 실전 팁 | `ctf-reverse/field-notes.md` | — |

### Windows(PE/DLL/.NET) rev — 도구+지식
> 기본 플랫폼은 Linux. Windows rev 는 Linux 호스트에서 대응(정적=Ghidra/angr, 동적=Qiling/Frida). SETUP.md §8.
| 상황 | 도구 | 지식 |
|---|---|---|
| PE/DLL 정적 | `decomp`(Ghidra) + `revq`(angr; PE 감지 배너) | `ctf-reverse/platforms.md`, `languages.md`, `anti-analysis.md` |
| PE 동적 (Wine 불필요) | `solve/_template/rev/qiling_trace.py`(Qiling 에뮬) + Frida | `ctf-reverse/tools-dynamic.md`, `tools-emulation.md` |
| .exe 실행/재현 | `wine`(symsolve concrete-verify 가 PE면 자동) | — |
| .NET / Unity(IL2CPP) | `ilspycmd`/ILSpy · il2cppdumper · monodis | `ctf-reverse/languages.md`, `platforms.md` |

## writeup 작성 (SOLVE 후 — 참고용)
- `knowledge/ctf-writeup/SKILL.md` — 로컬 분석 기록 형식 참고(메타 + Summary + 1~3 step + **하나의 완결 스크립트**).
- `doctrine/WRITEUP_FORMAT.md` — 문제 정보, 재현 과정, 코드·입력·명령어, 증거 캡처, AI·자동화 사용 사실 기재를 위한 공통 제출 양식.
- 원칙: 재현 가능한 로컬 스크립트 하나, 터미널 덤프 복붙 금지, 1~3단계 간결.

## 채택 안 하는 부분 (우리 상위 규율이 이김)
- SKILL.md의 **tool-setup / 설치 절 / 자체 gdb quickstart** → 무시. 우리 도구가 상위:
  - GDB = 시스템 gdb 12.1 + **pwndbg**(`~/.gdbinit`에서 자동 source, 확인됨).
  - 관찰 = `gdbq`(정적) / `pwnkit`의 `CLEAN_GS`·`snapscript`·`run_batch`(SNAP 핀포인트) / `pwnclean` 필터.
  - 상태 = `state` 버스, offset/primitive 재도출 금지.
- SKILL의 driver식 pivot 문구("switch to /ctf-web" 등)도 참고만. 판정은 SOLVABILITY.md.
- Windows 전용 실행 기법 언급 → 우리 미션(x86-64 linux) 밖, 무시.

## 커버리지 요약
- **pwn** (`ctf-skills/`): 로컬 메모리 안전성 분석, allocator 동작, format string, 기본 제어흐름 분석.
- **rev** (`ctf-reverse/`): anti-analysis · 언어별 리버싱 · RE 패턴 · VM · 툴/에뮬레이션.
- 얇은 곳: type confusion 심화(=바이너리 RE 본체라 카탈로그 무관).

## vendored 출처 / 미vendoring
- 출처: **github.com/ljagiello/ctf-skills (MIT)**. 매핑: pwn=`ctf-skills/`(업스트림 ctf-pwn) · rev=`ctf-reverse/` · writeup=`ctf-writeup/`.
- 업스트림엔 `ctf-web`·`ctf-crypto`·`ctf-forensics`·`ctf-osint`·`ctf-malware`·`ctf-misc`·`ctf-ai-ml` 도 있으나 **pwn/rev 스코프상 미vendoring** (필요 시 동일 방식으로 추가).
