# Mirror Mirror - state

## Metadata
- Category: Reversing
- Challenge ID: 29
- Artifact: `mirror.py`
- Status: solved, locally verified

## Observations
- Single Python script.
- `verify()` reads its own source with `open(__file__, "r")`.
- It locates the literal `MIRROR_SURFACE_DO_NOT_SCRATCH`.
- It computes `sha256(src[pivot:pivot+300])`.
- A fixed `blob` is XORed with the digest and repeating key `MirrorMirror`.

## Verified Path
- Recomputed the exact source slice from the downloaded `mirror.py`.
- Recovered the expected password by reversing the XOR loop.
- Ran the original script with the recovered password.
- Concrete verification output: `The reflection clears!`

## Flag
`bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}`

