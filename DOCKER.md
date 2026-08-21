# Docker Runtime Reproduction

The CTF-RAT Codex analysis container does not receive the host Docker socket,
`SYS_PTRACE`, or an unconfined seccomp profile. Start and manage challenge
service containers from the host. Codex automation stops after primitive PASS;
any final execution is an operator handoff.

CTF pwn problems often ship a `Dockerfile`. Treat it as the authoritative
runtime description: libc, loader, env, cwd, user, file permissions, and service
wrapper all matter. Prefer Docker verification before hand-built host emulation.

## 0. Prerequisites

Install a container runtime once on the host:

```bash
sudo apt update
sudo apt install -y docker.io
sudo usermod -aG docker "$USER"
newgrp docker
docker run --rm hello-world
```

If the current non-login shell still cannot access `/var/run/docker.sock` after
`usermod`, either open a new login shell or prefix commands with
`sg docker -c 'docker ...'`.

If Docker is unavailable in the current environment, use the fallback in
`reference/glibc/SOURCES.md`, then patch with the extracted `libc.so.6` and
`ld-linux-x86-64.so.2`.

## 1. Build The Challenge Image

Run this in the extracted challenge directory, next to the provided `Dockerfile`:

```bash
docker build -t ctf-chal:local .
```

Do not rewrite the Dockerfile unless the challenge requires it. In particular,
keep the base image digest, `USER`, `WORKDIR`, copied files, permissions, and
service command intact.

## 2. Run A Local Remote-Equivalent Service

Bind only to loopback and use the exposed service port from the Dockerfile:

```bash
docker run --rm --name ctf-chal \
  -p 127.0.0.1:18080:8080 \
  ctf-chal:local
```

Then allow only that local target while testing:

```bash
ctfguard begin <chal-name> 127.0.0.1:18080
ctfguard nc 127.0.0.1 18080
```

This catches differences that a direct `./prob` run misses: `socat`/xinetd
wrapping, cwd, argv/env length, file permissions, non-root user, and container
libc.

## 3. Extract libc And Loader From The Image

For exploit development outside the container, copy the exact runtime libc and
dynamic loader out of the built image:

```bash
cid="$(docker create ctf-chal:local)"
docker cp -L "$cid":/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
docker cp -L "$cid":/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2
docker rm "$cid"
sha256sum ./libc.so.6 ./ld-linux-x86-64.so.2
```

Patch a local copy of the binary:

```bash
cp ./deploy/prob ./prob.local
patchelf --set-interpreter "$PWD/ld-linux-x86-64.so.2" \
         --set-rpath "$PWD" \
         ./prob.local
ldd ./prob.local
```

Use `./prob.local` for quick local GDB and `127.0.0.1:18080` for final
remote-equivalent verification.

## 4. Debug Inside The Container

When the bug depends on the wrapper or exact process environment, debug inside a
container built from the same image:

```bash
docker run --rm -it \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "$PWD":/work -w /work \
  --entrypoint /bin/bash \
  ctf-chal:local
```

Install debug tools only in a disposable debug image or interactive throwaway
container. Do not use an apt-updated image as proof of final exploit reliability
if the challenge image itself is pinned.

## 5. Final Verification Checklist

- `recon`/`checksec` results are from the challenge binary.
- `libc.so.6` and `ld-linux-x86-64.so.2` hashes come from the built image.
- `libcgate .` shows the expected Dockerfile and does not point the loader at
  the host `/lib` path.
- Exploit succeeds against the loopback Docker service, not only `./prob.local`.
- `state primitive ... pass` records the remote-equivalent evidence.
- Heap exploits record allocator evidence before blaming libc: tcache count,
  head, returned chunks, and safe-linking `target ^ (chunk >> 12)` when relevant.
- Do not claim "remote libc mismatch" unless Docker-loopback verification fails
  in the same way or the remote leaks a libc build-id/hash/offset set that
  contradicts the Docker image.
- Real remote testing uses only the challenge-provided `host:port` through
  `ctfguard nc` after the target is allowlisted.
