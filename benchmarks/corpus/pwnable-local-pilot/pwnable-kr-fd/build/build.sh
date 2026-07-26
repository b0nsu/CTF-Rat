#!/bin/sh
set -eu
mkdir -p ../bin
exec gcc -m32 -fPIE -pie -O0 -o ../bin/fd ../src/fd.c
