#!/usr/bin/env python3
"""Concrete smoke test for the flattened predicate in an angr state."""

from pathlib import Path

import angr
import claripy


ROOT = Path(__file__).resolve().parent
BIN = ROOT / "target_obf"
BASE = 0x400000
OBJ = 0x50000000
STACK = 0x7FFF00000000
RETURN = BASE + 0x25B4FF


def main() -> None:
    project = angr.Project(str(BIN), main_opts={"base_addr": BASE}, auto_load_libs=False)
    state = project.factory.blank_state(addr=BASE + 0x165820)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    state.memory.store(OBJ, (ROOT / "pred_pre.bin").read_bytes())
    # The dumped object is post-check. Recreate the predicate entry state and
    # leave only its 64-byte transformed-state input symbolic.
    state.memory.store(OBJ + 0x80, claripy.BVV(0, 64), endness=project.arch.memory_endness)
    transformed = [claripy.BVS(f"state_{index:02d}", 8) for index in range(0x40)]
    for index, byte in enumerate(transformed):
        state.memory.store(OBJ + 0x30 + index, byte)
    state.regs.rdi = OBJ
    state.regs.rsp = STACK - 8
    state.memory.store(STACK - 8, RETURN, endness=project.arch.memory_endness)

    simgr = project.factory.simgr(state)
    for step in range(100_000):
        if not simgr.active:
            break
        if any(item.addr == RETURN for item in simgr.active):
            hit = next(item for item in simgr.active if item.addr == RETURN)
            mask = hit.memory.load(OBJ + 0x80, 8, endness=project.arch.memory_endness)
            print(f"returned step={step} rax={hit.regs.rax} mask={mask}")
            print(f"constraints={len(hit.solver.constraints)}")
            # This checks that the reconstructed predicate has a satisfiable
            # success path before attempting inversion of the input transform.
            hit.solver.add(hit.regs.rax == 1)
            print(f"success_sat={hit.solver.satisfiable()}")
            return
        if step % 10_000 == 0:
            print(f"step={step} active={len(simgr.active)} addr={simgr.active[0].addr:#x}", flush=True)
        simgr.step(num_inst=1)
        if len(simgr.active) > 1:
            print(f"split at step={step}: {len(simgr.active)} states", flush=True)
            simgr.active = simgr.active[:1]
    print(f"stopped steps={step} active={len(simgr.active)} errored={len(simgr.errored)}")
    if simgr.active:
        print(f"last_addr={simgr.active[0].addr:#x}")
    if simgr.errored:
        print(simgr.errored[0].error)


if __name__ == "__main__":
    main()
