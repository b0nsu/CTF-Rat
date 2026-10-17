# Raw executable and multi-image challenge ingestion

This workflow extends the existing `rat`, `revq`, `newchal` and `rat.run/v1` contracts.
It does **not** add an automatic decompiler, disk forensics engine or guest-VM lifter.

## Discover raw artifacts first

```sh
rat route drive0 --fast --format json
```

A boot signature at file offset `0x1fe` is only a **candidate**. A floppy size
or a FAT marker likewise does not establish code architecture, executable
segments, privilege mode, address mapping or whether a filesystem is valid.
The initial route preserves these uncertainties and recommends an explicit load
mapping rather than starting whole-image CFG recovery.

## Opt in to raw-code analysis

If independent evidence has identified an executable **supported** stage,
supply all three hints (none are guessed):

```sh
rat route stage.bin --arch i386 --base 0x10000 --entry 0x10000
revq stage.bin --arch i386 --base 0x10000 --entry 0x10000 --funcs
rat query func stage.bin 0x10000 --arch i386 --base 0x10000 --entry 0x10000
```

These are examples, **not** inferred addresses for an arbitrary boot sector.
The implementation supports X86/i386, AMD64/x86_64, ARM and AArch64 in the
explicit blob configuration. For raw 16-bit BIOS real-mode code or a
mode-switching bootloader, using `i386` does not make CFGFast a validated
16-bit loader. First isolate a known compatible execution stage, or use a
mode-aware external analysis workflow.

Explicit raw mappings use angr's blob loader. `--fast` (ELF binutils mode)
is incompatible with blob hints. The binary digest and normalized load spec
both contribute to cache identity. Query commands need the **same** spec to
recover the intended address space; the route does not silently persist or
invent loader parameters.
Even when a raw stage has no boot or disk signature, the route records the
operator-supplied mapping and offers a bounded entry-function query. The
function card keeps the runtime load address unresolved and does not suggest
the ELF/PE decompiler for raw code.

## Scaffold a floppy/image set

```sh
newchal bumpy drive0 \
  --artifact image=drive1 \
  --artifact image=drive2 \
  --artifact image=drive3 \
  --artifact runner=run.sh
```

`--artifact` is repeatable. Roles are `image`, `runner`, and `extra`.
Every supplied regular file is copied by basename after validation. Files
that collide with each other or with generated solve files are rejected.

The existing `solve/bumpy/run.json` retains `rat.run/v1` and records a
SHA-256 digest and size for each input. A runner is inspected **statically**;
the kit never executes it during ingestion. Up to four candidate
`qemu-system-*` command lines are recorded with a source digest and an
unresolved-shell marker. They remain *hints*, not a verified execution
environment. `rat brief drive0` can display bounded, manifest-bound QEMU
hints if the manifest's primary binary digest matches the analyzed file.

Disk filesystem traversal, sector carving, guest ISA recovery and #102
dispatcher/VM semantics recovery remain separate, measured follow-up work.
