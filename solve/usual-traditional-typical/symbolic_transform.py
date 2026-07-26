#!/usr/bin/env python3
"""Execute the pre-thread input transform from a live, fixed-PIE snapshot."""

from pathlib import Path

import angr
import claripy


ROOT = Path(__file__).resolve().parent
BASE = 0x555555554000
RBP = 0x7FFFFFFFDA10
RSP = 0x7FFFFFFFD898
OBJ = 0x7FFFFFFFD980
STACK_LOW = RBP - 0x23000
GLOBAL_LOW = BASE + 0x267780
START = BASE + 0x2376D0
RETURN = BASE + 0x161487
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789_"


def main() -> None:
    project = angr.Project(str(ROOT / "target_obf"), main_opts={"base_addr": BASE}, auto_load_libs=False)
    project.hook(BASE + 0x2686B0, angr.SIM_PROCEDURES["libc"]["memset"]())
    state = project.factory.blank_state(addr=START)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.memory.store(STACK_LOW, (ROOT / "check_entry_stack.bin").read_bytes())
    state.memory.store(GLOBAL_LOW, (ROOT / "check_entry_globals.bin").read_bytes())
    state.memory.store(OBJ, (ROOT / "check_entry_object.bin").read_bytes())
    raw = [claripy.BVS(f"body_{i:02d}", 8) for i in range(36)]
    for i, byte in enumerate(raw):
        state.memory.store(OBJ + i, byte)
        state.solver.add(claripy.Or(*(byte == c for c in range(37))))
    state.regs.rdi = OBJ
    state.regs.rbp = RBP
    state.regs.rsp = RSP
    state.memory.store(RSP, RETURN, endness=project.arch.memory_endness)

    simgr = project.factory.simgr(state)
    for step in range(20_000):
        hit = next((item for item in simgr.active if item.addr == RETURN), None)
        if hit is not None:
            print(f"returned step={step} constraints={len(hit.solver.constraints)}")
            print("state=" + repr(hit.memory.load(OBJ + 0x30, 0x40)))
            return
        if not simgr.active:
            break
        if step % 500 == 0:
            print(f"step={step} active={len(simgr.active)} addr={simgr.active[0].addr:#x}", flush=True)
        simgr.step(num_inst=100)
        if len(simgr.active) > 1:
            simgr.active = simgr.active[:1]
    print(f"stopped active={len(simgr.active)} errored={len(simgr.errored)}")
    if simgr.active:
        print(f"last={simgr.active[0].addr:#x}")
    if simgr.errored:
        print(simgr.errored[0].error)
        print("recent=" + ", ".join(hex(addr) for addr in simgr.errored[0].state.history.bbl_addrs.hardcopy[-20:]))


if __name__ == "__main__":
    main()
