# Proper Pwning

## Meta

- Category: pwn
- Challenge ID: 17
- Remote: `0.cloud.chals.io:21543`
- Flag: `bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}`

## Summary

The binary is a simple no-PIE ret2win challenge with four unchecked `gets` calls.
The first three gates require overwriting adjacent stack variables. The final
`treasure_room` buffer allows return-address control and jumps to `win`.

## Offsets

```text
win              0x40123b
ret              0x40101a
gate1 gate       0x10c
gate2 chicken    0x208
gate2 gate       0x20c
gate3 gate       0x4c
treasure ret     0x1a78
```

`ret` is needed before `win` to keep the stack aligned for `system("/bin/cat flag.txt")`.

## Exploit

See `exploit.py`.
