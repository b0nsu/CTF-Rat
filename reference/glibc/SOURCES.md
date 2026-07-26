# glibc — 리스트 + 다운로드 출처 (libs 는 축적하지 않음)

실제 glibc 바이너리(`libc.so.6`/`ld`/디버그심볼)는 **커밋하지 않는다**(수백 MB). 대신:
- `list` — 버전 **카탈로그**(Ubuntu 릴리스별 libc6 버전, amd64/i386). 최신 계열 포함:
  **2.41**(Ubuntu 25.10 Plucky) · 2.40(24.10 Oracular) · 2.39(24.04 Noble) · 2.35(22.04 Jammy).
- `glibc-fetch <version> [arch]` — 필요한 버전만 로컬 `libs/<version>_<arch>/` 로 내려받음(gitignore).

## 다운로드 출처 (glibc-fetch 가 순서대로 시도)
1. **Ubuntu pool (현행)**: `http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_<ver>_<arch>.deb`
2. **old-releases** (EOL 릴리스): `http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/…`
3. **ports** (non-amd64: arm64/i386 등): `http://ports.ubuntu.com/ubuntu-ports/pool/main/g/glibc/…`
   - 디버그 심볼은 `libc6-dbg_<ver>_<arch>.deb` (동일 경로).

## 대안(수동/보강)
- **libc-database**: `https://github.com/niklasb/libc-database` — `./download <id>` / `./find` (오프셋 역검색).
- **libc.rip** API: 심볼 오프셋으로 libc 식별 — `https://libc.rip/` (`/api/find`).
- **pwninit**: 챌린지 dir 에서 `pwninit` → libc/ld 자동 매칭+patchelf (SETUP.md 참고).
- **Dockerfile 제공 시 우선순위**: [../../DOCKER.md](../../DOCKER.md) 절차로 이미지를 빌드하고,
  이미지 안의 실제 `libc.so.6`/`ld-linux` 를 추출한다. `glibc-fetch` 는 Docker가 없거나
  Dockerfile이 없을 때의 fallback이다.
- **진단 순서**: `libcgate <chal-dir>` 로 provenance를 확인한다. heap/tcache exploit 실패를
  remote libc mismatch 로 단정하기 전, Docker loopback과 tcache count/head/fd 증거를 먼저 남긴다.

## 카탈로그 갱신
`list` 는 스냅샷이다. 최신 반영은 Launchpad 에서 확인:
- glibc 소스 패키지: `https://launchpad.net/ubuntu/+source/glibc`
- 릴리스별: noble(24.04)/oracular(24.10)/plucky(25.10) 페이지의 libc6 버전.

## 관련
- one_gadget 오프셋 스냅샷: `reference/libc-offsets/<version>_amd64.txt` (7개 주요 버전).
- 힙 기법은 버전 게이팅 필수 — `knowledge/GROUNDING_INDEX.md`(how2heap 버전태그 우선).
