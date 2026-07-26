#!/bin/sh
secret_dir=`mktemp -d --tmpdir=/tmp`
mount -n -o size=50m -t tmpfs tmpfs $secret_dir
cp /tiny_hard `echo $secret_dir`
chown -R tiny_hard_pwn:tiny_hard_pwn `echo $secret_dir`
chmod 333 /tmp
chmod 777 `echo $secret_dir`
chmod 6755 `echo $secret_dir`/tiny_hard
cd `echo $secret_dir`
su tiny_hard -c /bin/bash

