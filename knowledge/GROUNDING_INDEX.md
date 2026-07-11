# Grounding Index — 유형(vuln class) → 지식소스 매핑

> **목적**: triage에서 vuln class 확정 후, *어떤 파일을* grounding으로 당길지 결정하는 라우터.
> 지식은 **grounding**(개념 확인)이지 **driver**(풀이 대행) 아님. 확신은 SOLVABILITY.md 게이트대로
> **이 바이너리에서 fresh 도출 + 로컬 실증**했을 때만. 답/writeup 검색 금지.

## 사용 규율 (context 규율 = CLAUDE.md 승계)
1. **통째 로드 금지.** `knowledge/ctf-skills/*.md`는 총 ~9000줄. triage로 class 확정된 **1개 파일만**.
2. **큰 읽기는 subagent(Task)에 위임** → 결론(관련 기법명·전제·완화조건·코드 스니펫)만 회수. 메인 컨텍스트에 원문 붙이지 말 것.
3. 각 파일 첫머리에 **Table of Contents** 있음 → 먼저 ToC만 grep(`grep -m30 '^##' <file>`)해 섹션 특정 후, 그 섹션만 발췌.
4. **오프셋/gadget/상수는 여기서 recall 금지** — 전부 바이너리·gdb 실측 후 `state offset`. 문서 값은 개념 예시일 뿐.
5. glibc 게이팅은 **how2heap(버전태그) 우선**, ctf-skills는 폭 보강.

## 소스 3축
| 소스 | 경로 | 강점 |
|---|---|---|
| how2heap | `~/gnnPwn/data/rag_corpus/how2heap/` | glibc 버전별 heap 정밀(safe-linking/hook/tcache 게이팅) |
| ctf-skills | `knowledge/ctf-skills/` (vendored, MIT) | 유형 폭: musl·custom allocator·FSOP 최신·sandbox·ROP advanced |
| kernel env | `kernel/` + kernel*.md | 커널 (환경이 상위, md는 개념 참조) |

## triage class → 파일 라우팅
| vuln class (triage) | 1차 grounding | 보조 |
|---|---|---|
| stack overflow / ret2win / ret2libc | `ctf-skills/overflow-basics.md` | `rop-and-shellcode.md` |
| ROP 체인 / leak 후 재진입 / shellcode | `ctf-skills/rop-and-shellcode.md` | `overflow-basics.md` |
| stack pivot / leave;ret / SROP / ret2csu / 고급 ROP | `ctf-skills/rop-advanced.md` | — |
| format string (GOT/fmt leak/%n) | `ctf-skills/format-string.md` | — |
| heap glibc (tcache/fastbin/UAF/overlap/House of *) | **how2heap(버전 확정 후)** | `ctf-skills/heap-techniques.md`, `heap-techniques-2.md` |
| FSOP / _IO_FILE / House of Apple2 / vtable | `ctf-skills/heap-fsop.md` | `heap-techniques.md`(Apple2 절) |
| non-glibc heap (musl / nginx pool / talloc) | `ctf-skills/heap-techniques-2.md` | — |
| seccomp / ORW / openat2 우회 | `ctf-skills/advanced.md`(Seccomp Advanced) | `seccomp-tools dump` |
| sandbox escape (python / FUSE·CUSE / chroot) | `ctf-skills/sandbox-escape.md` | — |
| custom VM / bytecode interpreter | `ctf-skills/sandbox-escape.md`(VM Exploitation 절) | ※ 본체는 바이너리 RE |
| 커널 (KASLR/SMEP/SMAP/ret2usr/cred/modprobe) | `kernel/CLAUDE.md` + `kernel.md`/`kernel-techniques.md`/`kernel-bypass.md` | — |
| 잡다한 실전 팁 / 디버깅 관용구 | `ctf-skills/field-notes.md` | — |
| 위에 안 잡히는 다단계 체인 | `ctf-skills/advanced.md`, `advanced-exploits{,-2..-5}.md` | ToC 먼저 훑고 해당 절만 |

## 채택 안 하는 부분 (우리 상위 규율이 이김)
- SKILL.md의 **tool-setup / 설치 절 / 자체 gdb quickstart** → 무시. 우리 도구가 상위:
  - GDB = 시스템 gdb 12.1 + **pwndbg**(`~/.gdbinit`에서 자동 source, 확인됨).
  - 관찰 = `gdbq`(정적) / `pwnkit`의 `CLEAN_GS`·`snapscript`·`run_batch`(SNAP 핀포인트) / `pwnclean` 필터.
  - 상태 = `state` 버스, offset/primitive 재도출 금지.
- SKILL의 driver식 pivot 문구("switch to /ctf-web" 등)도 참고만. 판정은 SOLVABILITY.md.
- Windows exploit 언급 → 우리 미션(x86-64 linux) 밖, 무시.

## 커버리지 요약 (2026-07-09 기준)
userland 주류 유형 개념 공백 거의 없음. ctf-skills가 how2heap 대비 채우는 핵심:
**musl/커스텀 allocator · sandbox escape · custom VM · FSOP 최신형 · advanced ROP.**
남는 얇은 곳: type confusion 심화(=바이너리 RE 본체라 카탈로그 무관).
