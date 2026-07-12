# Mirror Mirror

## Summary
The checker derives the accepted input from its own source code. It hashes a 300 byte slice starting at `MIRROR_SURFACE_DO_NOT_SCRATCH`, then XORs the result with a static blob and the repeating key `MirrorMirror`.

## Solution
The relevant logic is:

```python
specular_map = hashlib.sha256(src[pivot:pivot+300].encode()).digest()
reflection_byte = specular_map[i % len(specular_map)] ^ ord("MirrorMirror"[i % 12])
flag += chr(blob[i] ^ reflection_byte)
```

So the solve is just to run the same derivation on the original file bytes and print the reconstructed string.

## Verification
The recovered input was passed back into `mirror.py`; the program printed:

```text
The reflection clears!
```

## Flag
```text
bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}
```

