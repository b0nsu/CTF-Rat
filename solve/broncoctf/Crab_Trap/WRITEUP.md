# Crab Trap

## Meta

- Category: pwn
- Challenge ID: 42
- Remote: `0.cloud.chals.io:34381`
- Flag: `bronco{h0w_c4n_mr_kr4b5_c0de}`

## Summary

The service accepts up to 512 bytes of shellcode, then applies a seccomp policy that
allows only `open`, `read`, and `write`. `execve` is blocked, so the exploit uses
ORW shellcode to read `flag.txt`.

## Exploit

See `exploit.py`.
