# Dog Simulator

## Meta

- Category: rev
- Challenge ID: 46
- Attachment: `dog-sim-mac`
- Status: unsolved

## Notes

The attachment is an ARM64 Mach-O PIE. The local Linux host cannot run it directly.
Static reversing with radare2 recovered a six-day action loop:

```text
1 Bark    +10
2 Fetch   +20
3 Sit     +15
4 Eat     +10
5 Zoomies -5
6 Speak   typed command
```

Recovered checks:

- Speak normalizes alphabetic characters to lowercase.
- One branch checks normalized speak text against `gremlin`.
- One FNV-1a style hash target is `0x9f58d866`.
- Lowercase hash preimages found with z3:
  - `rjeeqwm` length 7
  - `lhfzzflsyciu` length 12

Final input sequence still needs recovery. The final path checks score, action
counters, speak-letter total, state, and two checksums before generating the finale.
