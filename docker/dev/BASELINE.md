# 검증 환경 baseline (작업 전 준비단계 기록)

날짜: 2026-08-23 · 브랜치: `chore/dev-env`

## 환경
- 호스트: macOS arm64 (Apple Silicon)
- 런타임: Colima `default` 프로필 = **Linux x86_64 게스트** (4 CPU / 8 GiB), docker context `colima`
- dev 이미지: `ctf-rat-dev:local` (ubuntu:22.04, glibc 2.35) — **angr 9.2.213 · pwntools · gdb 12.1** · 1.43GB
- 빌드: `docker/dev/build.sh` (`--platform linux/amd64`)

## baseline 결과 (컨테이너 `docker/dev/test.sh`)
- `revq selftest` ✅ ALL GREEN
- `symsolve selftest` ✅ ALL GREEN
- full unittest: **123개 중 121 통과, 2 error** (macOS 호스트는 13 fail + 15 error였음 → 전부 환경성)

### 남은 2 error — 둘 다 non-blocking (환경/옵션)
| 테스트 | 원인 | 판정 |
|---|---|---|
| `test_qiling_instruction_hook_stops_at_budget` | qiling 미설치(옵션 dep, Windows rev 전용) | M0~M3 무관, 스킵 |
| `test_pwncrash_reproduces_local_core_evidence` | 에뮬 x86_64에서 gdb core-dump 거동 차이 | pwn 전용, M0~M3(rev) 무관 |

두 error 모두 레포 코드 breakage가 아니라 dev 이미지의 의도적 최소구성(qiling 제외) + 에뮬레이션 특성.
필요 시 `pip install qiling`으로 첫째는 해소 가능(무거워 기본 제외). pwncrash는 M3/pwn 착수 시 재평가.

## 결론
M0(telemetry)·M1(slim entrypoint)·M2(cache)·M3(rev features)의 **코드 작성·unit test·측정에 필요한
환경이 준비됨.** gdb 기반 M3-2 difftrace도 이 x86_64 게스트에서 네이티브로 동작 가능.
