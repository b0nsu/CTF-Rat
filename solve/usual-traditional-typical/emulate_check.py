#!/usr/bin/env python3
"""Replay the live mask-building path from 0x161474 in angr."""

from pathlib import Path

import angr


ROOT = Path(__file__).resolve().parent
# The snapshots contain absolute pointers from GDB's fixed PIE base.
BASE = 0x555555554000
RBP = 0x7FFFFFFFD9E0
RSP = 0x7FFFFFFFD870
STACK_LOW = RBP - 0x23000
GLOBAL_LOW = BASE + 0x267780
START = BASE + 0x161487
DONE = BASE + 0x1614A6


class Ret0(angr.SimProcedure):
    def run(self, *args):
        return 0


def main() -> None:
    project = angr.Project(str(ROOT / "target_obf"), main_opts={"base_addr": BASE}, auto_load_libs=False)
    # The live snapshot carries resolved GOT entries. Hook the PLT entry before
    # its indirect jump so angr stays inside the modelled address space.
    project.hook(BASE + 0x2686B0, angr.SIM_PROCEDURES["libc"]["memset"]())
    project.hook(BASE + 0x268700, angr.SIM_PROCEDURES["libc"]["malloc"]())
    project.hook(BASE + 0x268710, Ret0())
    state = project.factory.blank_state(addr=START)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.memory.store(STACK_LOW, (ROOT / "check_mid_stack.bin").read_bytes())
    state.memory.store(GLOBAL_LOW, (ROOT / "check_mid_globals.bin").read_bytes())
    state.regs.rbp = RBP
    state.regs.rsp = RSP

    simgr = project.factory.simgr(state)
    for step in range(100_000):
        if not simgr.active:
            break
        if any(item.addr == DONE for item in simgr.active):
            hit = next(item for item in simgr.active if item.addr == DONE)
            mask = hit.memory.load(RBP - 0x10, 8, endness=project.arch.memory_endness)
            print(f"reached final call step={step} mask={hit.solver.eval(mask):#x}")
            return
        if step % 2_500 == 0:
            print(f"step={step} active={len(simgr.active)} addr={simgr.active[0].addr:#x}", flush=True)
        simgr.step()
        if len(simgr.active) > 1:
            print(f"split at step={step}: {len(simgr.active)} states", flush=True)
            simgr.active = simgr.active[:1]
    print(f"stopped steps={step} active={len(simgr.active)} errored={len(simgr.errored)}")
    if simgr.active:
        print(f"last_addr={simgr.active[0].addr:#x}")
    if simgr.errored:
        print(simgr.errored[0].error)
        print("recent=" + ", ".join(hex(addr) for addr in simgr.errored[0].state.history.bbl_addrs.hardcopy[-16:]))


if __name__ == "__main__":
    main()
