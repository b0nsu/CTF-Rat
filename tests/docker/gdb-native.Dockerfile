FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gdb python3 libc6-dbg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
