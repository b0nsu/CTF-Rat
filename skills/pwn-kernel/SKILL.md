# pwn-kernel

hot-path only — full technique catalog: `knowledge/ctf-skills/kernel.md` (+`kernel-techniques.md`, `kernel-bypass.md`); environment tooling in `kernel/` (`k_*`).

## SIGNALS
- Kernel-space imports/symbols (`copy_from_user`, `copy_to_user`, `kmalloc`, `kfree`, `module_init`/`module_exit`), a `.ko` module, or a bundled `vmlinux`/boot image alongside the challenge.

## FIRST ACTION
- Use `kernel/k_*` tooling (`k_run_qemu`, `k_dump_heap`, `k_kallsyms`/`k_raw_kallsyms`, `k_repack`) to stand up the actual target environment before reading the module statically — kernel exploits are environment-first, not just static-RE-first.
- `k_kallsyms` to confirm KASLR state and known symbol addresses before hypothesizing a technique.

## PIVOT
- The "kernel" surface is actually a userland driver-interaction bug reachable without kernel primitives → re-route to the matching pwn-* skill for the userland side.

## ESCALATE
- Any kernel exploitation step is inherently DEEP — never attempt local-Docker-only shortcuts that skip the real environment. Confirm `doctrine/SOLVABILITY.md` and `doctrine/PRIMITIVE_GATE.md` before assembling anything.
- SMEP/SMAP/KPTI bypass requirements uncertain → DEEP, confirm via the actual boot config (`k_run_qemu` boot args), not assumption.

## VERIFY
- typed STATE v2 PASS (`state primitive pass <rat.primitive/v1 doc.json>` — per `doctrine/PRIMITIVE_GATE.md`) only after a minimal primitive (e.g. controlled write via `copy_from_user` misuse) is demonstrated inside the real QEMU environment.
- SOLVED requires privilege escalation or flag read evidence from the actual booted kernel image (`k_run_qemu`), never a userland simulation.
