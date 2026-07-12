# Cat Simulator

## Summary
The binary is a small choice-based game. The normal ending only prints flavor text, but a hidden finale branch decrypts the flag when the action counts and talk-message length match.

## Solution
Disassembly showed the hidden branch after the 5 day loop:

```text
talk_count == 3
scratch_count == 1
eat_count == 1
total_talk_length == 32
final_score == 45
```

Any talk strings with total length 32 work. I used lengths `10`, `11`, and `11`, followed by scratch and eat.

## Verification
The Linux binary printed:

```text
Owner: awwww it said "bronco{fluffy_baby}"
```

## Flag
```text
bronco{fluffy_baby}
```

