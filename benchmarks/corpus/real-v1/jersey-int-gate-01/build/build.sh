#!/bin/sh
set -eu
mkdir -p ../bin
exec gcc -O2 -s -o ../bin/challenge ../src/challenge.c
