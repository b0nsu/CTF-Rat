# CTF-Rat 검증(verification) dev 컨테이너
# 목적: angr/pwntools/gdb 를 갖춘 Linux x86-64 환경에서 plan M0~M3 를 실행·측정.
# 챌린지용 Dockerfile 아님 (그건 DOCKER.md). 이건 kit 자체 개발/검증 환경.
#
# 빌드(반드시 amd64 — 호스트가 arm64여도):
#   docker build --platform linux/amd64 -t ctf-rat-dev:local docker/dev
# 실행(레포를 /work 로 마운트, ptrace 허용):
#   docker run --rm -it --platform linux/amd64 \
#     --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
#     -v "$PWD":/work -w /work ctf-rat-dev:local
#
# glibc 2.35 = reference/libc-offsets 계열과 일치하는 Ubuntu 22.04 기반.
FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# 시스템 도구 (SETUP.md §3) — gdb 는 M3-2 difftrace / rat-dyn breakpoint 에 필수
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv python3-dev \
        gdb build-essential file binutils patchelf xxd \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python 핵심 (SETUP.md §2). 컨테이너 전역 설치 — venv 불필요(격리된 이미지).
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install angr pwntools ropgadget

# 도구 PATH/PYTHONPATH (SETUP.md §1) — 레포는 /work 에 마운트
ENV PATH="/work/bin:${PATH}" \
    PYTHONPATH="/work/bin" \
    CTF_HOME="/work"

WORKDIR /work

# 스모크: 이미지가 최소 selftest 를 통과하는지(빌드시 레포 미마운트라 버전만 확인)
RUN python3 -c "import angr, pwn; print('angr', angr.__version__, '| pwntools ok')" \
    && gdb --version | head -1

CMD ["/bin/bash"]
