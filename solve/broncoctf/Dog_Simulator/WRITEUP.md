# Dog Simulator

## Meta

- Category: rev
- Challenge ID: 46
- Attachment: `dog-sim-mac`
- Flag: `bronco{mans_best_friend}`

## Summary

The attachment is an ARM64 Mach-O. Static analysis showed a six-day state machine
with action counters, score/bond/energy/mood checks, two speak inputs, and two
checksums. I used Unicorn to execute the real ARM64 `main` while hooking libc
functions (`fgets`, `puts`, `printf`, `snprintf`, `atoi`, `strlen`, etc.).

The successful routine is:

```text
2
3
1
6
lhfzzflsyciu
4
6
gremlin
```

The emulator reaches the finale and prints:

```text
Owner: awww he said "bronco{mans_best_friend}"
```

## Solver

See `emulate_dog.py`.
