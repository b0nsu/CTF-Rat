# C++ Unplugged

## Summary
The source is valid C++ structure with identifiers and operators obfuscated as song-title tokens. The flag is assembled by six functions named `part1` through `part6`.

## Solution
Map the token language back to C++ constructs and evaluate each part. The only subtle point was operator precedence: in C++, `%` binds tighter than `+`, so `60 + 12 % 7` evaluates to `65`, which is `A`.

The reconstructed pieces were:

```text
bron
co{
i_c@m3
_1n_lik3
_@_
s3gfAult}
```

## Verification
A macro header plus a tiny source normalization pass was used to compile the original logic. The compiled binary printed:

```text
The flag is bronco{i_c@m3_1n_lik3_@_s3gfAult}
```

## Flag
```text
bronco{i_c@m3_1n_lik3_@_s3gfAult}
```

