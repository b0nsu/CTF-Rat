# Cat Simulator - state

## Metadata
- Category: Reversing
- Challenge ID: 27
- Artifacts: `cat-sim-linux`, `cat-sim-mac`, `cat-sim-windows.exe`
- Primary artifact used: `cat-sim-linux`
- Status: solved, locally verified

## Observations
- Linux ELF is stripped PIE but small.
- Game loop has 5 days.
- Choices:
  - `1`: talk, score +25, then asks for text
  - `2`: scratch, score -50
  - `3`: eat, score +20
- Hidden finale branch checks action counts and talk text length.

## Verified Conditions
- Exactly 3 talk actions.
- Exactly 1 scratch action.
- Exactly 1 eat action.
- Total talk-message length must be 32.
- Final score becomes 45.

## Verified Input
One working sequence:

```text
1
AAAAAAAAAA
1
BBBBBBBBBBB
1
CCCCCCCCCCC
2
3
```

Talk lengths are `10 + 11 + 11 = 32`.

## Flag
`bronco{fluffy_baby}`

