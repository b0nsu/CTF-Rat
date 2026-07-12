# Crab Trap - state

## Metadata
- Category: Pwn
- Challenge ID: 42
- Artifact: remote-only
- Target: `0.cloud.chals.io:34381`
- Status: solved, remote verified

## Observations
- Service is a shellcode runner.
- Banner says allowed syscalls are `open`, `read`, `write`.
- `execve` is blocked by the challenge policy.
- Max shellcode size: 512 bytes.

## Verified Path
- Used amd64 ORW shellcode.
- Tried file path candidates:
  - `/flag.txt`: opened failed / leaked stack data
  - `flag.txt`: succeeded
  - `/flag`: failed
  - `flag`: failed
- Successful chain:
  - `open("flag.txt", 0)`
  - `read(fd, rsp, 0x100)`
  - `write(1, rsp, 0x100)`

## Flag
`bronco{h0w_c4n_mr_kr4b5_c0de}`

