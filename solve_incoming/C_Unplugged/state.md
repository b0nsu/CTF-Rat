# C++ Unplugged - state

## Metadata
- Category: Reversing
- Challenge ID: 18
- Artifact: `totallynormalcode.cpp`
- Status: solved, compiled-normalized verification

## Observations
- Source is C++ with keywords/operators replaced by song-title tokens.
- Important token mappings:
  - `EndGame` -> `;`
  - `FromTheStart` / `IsItOverNow` -> `(` / `)`
  - `BeginAgain` / `EndOfTime` -> `{` / `}`
  - `CountingStars` -> `int`
  - `CallItWhatYouWant` -> `string`
  - `Abcdefu` -> `char`
  - `Mine` -> `+=`
  - `PartOfMe` -> `%`
  - `BreakUpWithYourGirlfriendImBored` -> `/`
- The program concatenates `part1()` through `part6()`.

## Verified Path
- Reimplemented the token semantics in Python to compute each part.
- Corrected C++ operator precedence in `part6`: `60 + 12 % 7` gives `65`, `A`.
- Built a temporary macro header and normalized token stream for compilation.
- Verified compiled output prints the same flag.

## Flag
`bronco{i_c@m3_1n_lik3_@_s3gfAult}`

