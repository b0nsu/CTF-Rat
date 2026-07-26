#!/bin/sh
set -eu
mkdir -p ../bin
exec gcc -O0 -g -fno-stack-protector -fno-pie -no-pie -o ../bin/challenge ../src/challenge.c
