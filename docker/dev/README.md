# CTF-Rat 검증 dev 컨테이너

kit 자체(plan M0~M3)를 실행·측정하기 위한 Linux **x86-64** 환경. angr/pwntools/gdb 포함.
챌린지 실행용(`DOCKER.md`)과는 별개.

> 호스트가 arm64(Apple Silicon)여도 CTF-Rat는 x86-64 타겟이라 **반드시 `--platform linux/amd64`**.
> Docker Desktop의 Rosetta/qemu 에뮬로 amd64 ELF 실행·gdb가 동작한다.

## 빌드
```bash
docker build --platform linux/amd64 -t ctf-rat-dev:local docker/dev
```

## 실행 (레포를 /work 로 마운트, ptrace 허용 = gdb 필수)
```bash
docker run --rm -it --platform linux/amd64 \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD":/work -w /work ctf-rat-dev:local
```

## 컨테이너 안에서 baseline 검증 (SETUP.md §6)
```bash
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 -m unittest discover -s tests -p 'test_*.py'   # 여기선 sandbox preexec_fn 도 동작 → 진짜 green 기대
```

## 편의 스크립트
```bash
docker/dev/build.sh     # 빌드
docker/dev/shell.sh     # 위 run 을 그대로 실행(대화형 셸)
docker/dev/test.sh      # 컨테이너에서 full unittest 1회 실행하고 결과만 반환
```

## 주의
- Ghidra는 무거워 기본 이미지에서 제외(decomp는 옵션). 필요 시 별도로 `GHIDRA_HOME` 마운트.
- gdb amd64-under-emulation은 대부분 동작하나, 드물게 하드웨어 watchpoint류가 degrade될 수 있음.
  M3-2 difftrace는 소프트웨어 stepi/break 기반이라 영향 적음.
