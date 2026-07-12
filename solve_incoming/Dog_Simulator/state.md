# Dog Simulator - state

## Metadata
- Category: Reversing
- Challenge ID: 46
- Artifact: `dog-sim-mac`
- Platform: Mach-O arm64
- Status: solved via Unicorn emulation

## Observations
- Only macOS arm64 binary was provided.
- GNU `objdump` did not recognize the file format.
- Mach-O sections and symbols were parsed manually.
- `capstone` was available for arm64 disassembly.
- `unicorn` was available for emulating `main`.

## Emulator Notes
- Mapped `__TEXT` at `0x100000000`.
- Mapped `__DATA_CONST` at `0x100004000`.
- Stubbed libc calls:
  - `fgets`
  - `atoi`
  - `strlen`
  - `tolower`
  - `printf`
  - `puts`
  - `snprintf`
  - `fflush`
  - `clearerr`
- Added a fake `__DefaultRuneLocale` table so ASCII alphabet checks worked.

## Winning Conditions
- Six day sequence:
  - Fetch
  - Sit
  - Bark
  - Speak
  - Eat
  - Speak
- First speak command: `knqrgrylbmak`
- Second speak command: `gremlin`
- `knqrgrylbmak` is a 12-letter FNV preimage for target hash `0x9f58d866`.
- Final internal checks observed:
  - score: `55`
  - bond: `30`
  - energy: `36`
  - combo: `4`
  - `x23`: `0xf5d38524`
  - rolling command hash: `0x740a8a98`
  - speak total letters: `19`

## Verified Input
```text
2
3
1
6
knqrgrylbmak
4
6
gremlin
```

## Flag
`bronco{mans_best_friend}`

