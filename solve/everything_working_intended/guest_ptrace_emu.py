#!/usr/bin/env python3
import ctypes
import ctypes.util
import hashlib
import os
import signal
import socket
import struct
import sys

PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_O_TRACESYSGOOD = 1
PTRACE_SETOPTIONS = 0x4200
PTRACE_CONT = 7

SYS_READ = 0
SYS_WRITE = 1
SYS_OPEN = 2
SYS_CLOSE = 3
SYS_IOCTL = 16
SYS_OPENAT = 257

FD_CHRONICLE = 100
FD_TTY = 101

MASK = (1 << 64) - 1


class Regs(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong), ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong), ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong), ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong), ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong), ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong), ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong), ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong), ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong), ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong), ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong), ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong), ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong), ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long


def ptrace(req, pid, addr=0, data=0):
    ret = libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if ret == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return ret


def getregs(pid):
    regs = Regs()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def setregs(pid, regs):
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))


def read_mem(pid, addr, n):
    out = bytearray()
    for off in range(0, n, 8):
        word = ptrace(PTRACE_PEEKDATA, pid, addr + off, 0)
        out += struct.pack("<Q", word & MASK)
    return bytes(out[:n])


def write_mem(pid, addr, data):
    for off in range(0, len(data), 8):
        chunk = data[off:off + 8]
        if len(chunk) < 8:
            old = read_mem(pid, addr + off, 8)
            chunk = chunk + old[len(chunk):]
        ptrace(PTRACE_POKEDATA, pid, addr + off, struct.unpack("<Q", chunk)[0])


def read_cstr(pid, addr, limit=4096):
    data = bytearray()
    for i in range(limit):
        b = read_mem(pid, addr + i, 1)
        if b == b"\0":
            break
        data += b
    return bytes(data)


def u(x): return x & MASK
def u32(x): return x & 0xffffffff
def rol(x, n):
    n &= 63
    return u((x << n) | (x >> (64 - n))) if n else u(x)
def le64(b): return int.from_bytes(b, "little")
def st64(x): return u(x).to_bytes(8, "little")


def arx_round(s, k, idx):
    for i in range(6):
        a = (i + 1) % 6
        b = (i + 4) % 6
        rot = ((idx * 11 + i * 7) % 63) + 1
        s[i] = rol(u(s[i] + (s[a] ^ k)), rot)
        s[b] ^= u(s[i] + i + 0x9e3779b97f4a7c15)


def derive(seed, profile):
    buf = bytearray(b"FAULTLINE-SEED" + seed + bytes([profile]))
    h1 = hashlib.sha256(buf).digest()
    buf[0] ^= 0x5a
    h2 = hashlib.sha256(buf).digest()
    s = [le64(h1[i * 8:i * 8 + 8]) for i in range(4)]
    s += [le64(h2[:8]), le64(h2[8:16])]
    s[profile % 6] ^= 0x4546492d53544147
    for i in range(5):
        arx_round(s, 0xa0761d6478bd642f ^ i, i + 1)
    return [u(x) for x in s]


def module_init(s, trace_cb=None):
    tcnt = 0
    s = s[1:] + s[:1]
    if trace_cb:
        trace_cb("init-rot", tcnt, s)
    for r9 in range(0xe7037ed1a0b428db, 0xe7037ed1a0b428df):
        rdi = 0x9e3779b97f4a7c15
        r8 = u32(u32(r9) * 0xb + 0x18423ee4)
        while rdi != 0x9e3779b97f4a7c1b:
            j = (rdi - 0x9e3779b97f4a7c15) & MASK
            r13 = u32(rdi - 0x7f4a7c11) % 6
            idx = u32(rdi - 0x7f4a7c14) % 6
            eax = r8
            r8 = u32(r8 + 7)
            rsi = rol(u(s[j] + (s[idx] ^ r9)), (eax % 63) + 1)
            s[j] = rsi
            s[r13] ^= u(rsi + rdi)
            rdi = u(rdi + 1)
            tcnt += 1
            if trace_cb:
                trace_cb("init", tcnt, s)
    return s


def module_hello(s, profile):
    out = bytearray(40)
    out[:4] = struct.pack("<I", profile)
    out[4:8] = struct.pack("<I", 4)
    r11 = profile << 56
    r8 = 0
    edi = 9
    r10 = 17
    r9 = 0x6a09e667f3bcc909
    off = 8
    while edi != 0x35:
        rdx = rol(s[r8 // 8 + 2], edi)
        rax = s[r8 // 8] ^ r11
        rdx = rol(u((rdx ^ rax) + r9), r10)
        out[off:off + 8] = st64(rdx)
        edi = u32(edi + 0xb)
        r9 = u(r9 + 0x9e3779b97f4a7c15)
        r10 = u32(r10 + 7)
        r8 += 8
        off += 8
    return bytes(out)


def module_step(s, inp, trace_cb=None, trace_base=0):
    buf = bytearray(inp)
    cnt = int.from_bytes(buf[0x30:0x34], "little")
    v0 = le64(buf[0x20:0x28])
    v1 = le64(buf[0x28:0x30])
    r13 = u((cnt + 1) * 0xd6e8feb86659fd93)
    r9 = u32(cnt * 13)
    r15 = u32(cnt - 0x133111eb)
    rdi = 0x94d049bb133111eb
    r14 = 0xa0761d6478bd642f
    tcnt = trace_base
    while rdi != 0x94d049bb133111f1:
        j = (rdi - 0x94d049bb133111eb) & MASK
        r10 = u32(r15 + u32(rdi))
        tmp = le64(buf[((r10 * 8) & 0x18):((r10 * 8) & 0x18) + 8])
        rax = (v1 if (r10 & 1) else v0) ^ r13 ^ tmp
        rax = u(rax + u(s[j] + r14))
        q = ((u32(r9) * 0x4104105) & MASK) >> 32
        edx2 = u32(r9 - q)
        edx2 >>= 1
        edx2 = u32(edx2 + q)
        q2 = edx2 >> 5
        rot = u32(r9 - u32((q2 << 6) - q2)) + 1
        r9 = u32(r9 + 9)
        edx3 = u32(u32(rdi) - 0x133111e8)
        q = (edx3 * 0xaaaaaaab) >> 34
        idx = u32(edx3 - u32(q * 6))
        rax = rol(rax, rot)
        s[j] = rax
        s[idx] ^= u(rax + rdi)
        r14 = u(r14 + 0xa0761d6478bd642f)
        rdi = u(rdi + 1)
        tcnt += 1
        if trace_cb:
            trace_cb(f"step{cnt}", tcnt, s)
    esi = u32(cnt + 11)
    outoff = 0x38
    for k in range(4):
        r10 = rol(s[k + 2], esi) ^ s[k]
        tmp = le64(buf[(((k + 1) * 8) & 0x18):(((k + 1) * 8) & 0x18) + 8])
        buf[outoff:outoff + 8] = st64(r10 ^ tmp)
        esi = u32(esi + 5)
        outoff += 8
    return bytes(buf)


def run(seed, profile, server_stream=None, live_sock=None, raw_state=None):
    module_trace_refs = {}
    if os.environ.get("TRACE_MODULE_REFS"):
        for item in os.environ["TRACE_MODULE_REFS"].split(","):
            if item:
                module_trace_refs[item.lower()] = None
    module_trace_count = 0

    def module_trace_cb(label, count, state):
        nonlocal module_trace_count
        module_trace_count = count
        if module_trace_refs:
            hh = hashlib.sha256(b"".join(st64(x) for x in state)).hexdigest()[:32]
            if hh in module_trace_refs and module_trace_refs[hh] is None:
                module_trace_refs[hh] = (label, count, b"".join(st64(x) for x in state))

    s = module_init(raw_state[:] if raw_state is not None else derive(seed, profile), module_trace_cb if module_trace_refs else None)
    reads = []
    if server_stream is not None:
        reads = [server_stream[:40]] + [server_stream[40 + i * 32:40 + (i + 1) * 32] for i in range(11)]
    read_idx = 0
    writes = []
    ioctl_count = 0
    actions = {}
    checkpoints = {}
    if os.environ.get("TRACE_CHECKPOINTS"):
        for item in os.environ["TRACE_CHECKPOINTS"].split(","):
            if item:
                checkpoints[int(item, 0)] = None
    trace_tokens = {}
    if os.environ.get("TRACE_TOKENS"):
        for item in os.environ["TRACE_TOKENS"].split(","):
            k, v = item.split(":", 1)
            trace_tokens[int(k, 0)] = int(v, 0)
    patch_pos = int(os.environ.get("TRACE_PATCH_DWORD", "-1"))
    patch_qword = int(os.environ.get("TRACE_PATCH_QWORD", "-1"))
    patch_acc = os.environ.get("TRACE_PATCH_ACC") == "1"
    patch_acc_qword = os.environ.get("TRACE_PATCH_ACC_QWORD") == "1"
    jit_inner_checks = {}
    if os.environ.get("TRACE_JIT_INNER"):
        for item in os.environ["TRACE_JIT_INNER"].split(","):
            if not item:
                continue
            idx_s, op_s = item.split(":", 1)
            jit_inner_checks[(int(idx_s, 0), int(op_s, 0))] = None
    jit_dump_indexes = set()
    if os.environ.get("TRACE_JIT_INDEXES"):
        jit_dump_indexes = {int(x, 0) for x in os.environ["TRACE_JIT_INDEXES"].split(",") if x}
    jit_state_refs = {}
    if os.environ.get("TRACE_JIT_REFS"):
        for item in os.environ["TRACE_JIT_REFS"].split(","):
            if item:
                jit_state_refs[item.lower()] = None
    jit_find_inputs = {}
    if os.environ.get("TRACE_JIT_FIND_INPUTS"):
        for item in os.environ["TRACE_JIT_FIND_INPUTS"].split(","):
            if item:
                jit_find_inputs[int(item, 0)] = None
    update_trace_indexes = set()
    if os.environ.get("TRACE_UPDATE_INDEXES"):
        update_trace_indexes = {int(x, 0) for x in os.environ["TRACE_UPDATE_INDEXES"].split(",") if x}
    cast_map = {}
    if os.environ.get("EMU_CAST_MAP"):
        for item in os.environ["EMU_CAST_MAP"].split(","):
            if not item:
                continue
            k, v = item.split(":", 1)
            cast_map[int(k, 0)] = v
    trace_jit_code = os.environ.get("TRACE_JIT_CODE") == "1"
    bp_addr = 0x403d80 if checkpoints else None
    if jit_inner_checks or jit_dump_indexes or jit_state_refs or jit_find_inputs:
        bp_addr = 0x403d7b
    emulate_qemu64_cpuid = os.environ.get("EMU_QEMU64_CPUID") == "1"
    # qemu-x86_64 -cpu qemu64 values observed for chronicle_guest's two CPUID
    # wrappers.  Keeping these in the tracer avoids host-CPU leakage into JIT.
    qemu64_ext = {
        0xb9: 0x10000, 0xba: 0, 0xbb: 0x40, 0xbc: 0x10000,
        0xbd: 0, 0xbe: 0x40, 0xbf: 0x80000, 0xc0: 0x10,
        0xc1: 0x40, 0xc2: 0x1000000, 0xc3: 0x10, 0xc4: 0x40,
    }
    breakpoints = {}
    patched_guest = False
    stepping_bp = False

    guest = os.path.abspath("solve/everything_working_intended/initrd/chronicle_guest")
    pid = os.fork()
    if pid == 0:
        ptrace(PTRACE_TRACEME, 0, 0, 0)
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execl(guest, guest)

    os.waitpid(pid, 0)
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)
    def install_bp():
        nonlocal patched_guest
        if not patched_guest:
            if os.environ.get("PATCH_KEY0_HEX"):
                write_mem(pid, 0x47b180, bytes.fromhex(os.environ["PATCH_KEY0_HEX"]))
            if os.environ.get("PATCH_KEY1_HEX"):
                write_mem(pid, 0x47b160, bytes.fromhex(os.environ["PATCH_KEY1_HEX"]))
            if os.environ.get("PATCH_ADDR") and os.environ.get("PATCH_BYTES_HEX"):
                write_mem(pid, int(os.environ["PATCH_ADDR"], 0), bytes.fromhex(os.environ["PATCH_BYTES_HEX"]))
            if os.environ.get("PATCHES"):
                for item in os.environ["PATCHES"].split(","):
                    if not item:
                        continue
                    addr_s, hex_s = item.split(":", 1)
                    write_mem(pid, int(addr_s, 0), bytes.fromhex(hex_s))
            patched_guest = True
        addresses = []
        if bp_addr is not None:
            addresses.append(bp_addr)
        if trace_jit_code:
            addresses.append(0x4018a6)
        if update_trace_indexes:
            addresses.append(0x403740)
        if cast_map:
            addresses.append(0x4023c0)
        if emulate_qemu64_cpuid:
            addresses += [0x404a80, 0x404ba0]
        for addr in addresses:
            if addr in breakpoints:
                continue
            original = ptrace(PTRACE_PEEKDATA, pid, addr, 0) & MASK
            ptrace(PTRACE_POKEDATA, pid, addr, (original & ~0xff) | 0xcc)
            breakpoints[addr] = original
    entering = True
    while True:
        ptrace(PTRACE_SYSCALL, pid, 0, 0)
        wpid, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            break
        if not os.WIFSTOPPED(status):
            continue
        sig = os.WSTOPSIG(status)
        if breakpoints and sig == signal.SIGTRAP:
            regs = getregs(pid)
            hit_addr = regs.rip - 1
            if hit_addr in breakpoints:
                if trace_jit_code and hit_addr == 0x4018a6:
                    desc = regs.r14
                    code_addr = le64(read_mem(pid, desc, 8))
                    code_len = le64(read_mem(pid, desc + 8, 8))
                    code_len = min(code_len, 0x4000)
                    path = os.environ.get("TRACE_JIT_CODE_OUT", "/tmp/chronicle_jit.bin")
                    with open(path, "wb") as f:
                        f.write(read_mem(pid, code_addr, code_len))
                    print(f"jit_code addr={code_addr:#x} len={code_len:#x} out={path}", file=sys.stderr)
                    if os.environ.get("JIT_PATCHES"):
                        for item in os.environ["JIT_PATCHES"].split(","):
                            if not item:
                                continue
                            off_s, hex_s = item.split(":", 1)
                            off = int(off_s, 0)
                            patch = bytes.fromhex(hex_s)
                            if off + len(patch) <= code_len:
                                write_mem(pid, code_addr + off, patch)
                                print(f"jit_patch off={off:#x} bytes={hex_s}", file=sys.stderr)
                    trace_jit_code = False
                if update_trace_indexes and hit_addr == 0x403740:
                    idx = regs.rdx & 0xffffffff
                    op = regs.rcx & 0xffffffff
                    if idx in update_trace_indexes:
                        meta_addr = regs.r9 + 0x98 + (op % 0x60) * 0x18
                        meta = read_mem(pid, meta_addr, 0x18)
                        before = read_mem(pid, regs.rdi, 48)
                        print(f"update idx {idx} op {op:#x} in {regs.rsi & 0xffffffff:#x} val {regs.r8:#x} meta {meta.hex()} before {before.hex()}", file=sys.stderr)
                if cast_map and hit_addr == 0x4023c0:
                    typ = regs.rsi & 0xffffffff
                    if typ in cast_map:
                        x = regs.rdi & MASK
                        mode = cast_map[typ]
                        if mode == "full":
                            y = x
                        elif mode == "z32":
                            y = x & 0xffffffff
                        elif mode == "s32":
                            y = x & 0xffffffff
                            if y & 0x80000000:
                                y |= 0xffffffff00000000
                        elif mode == "z48":
                            y = x & 0xffffffffffff
                        elif mode == "s48":
                            y = x & 0xffffffffffff
                            if y & 0x800000000000:
                                y |= 0xffff000000000000
                        else:
                            raise ValueError(f"unknown cast mode {mode}")
                        ret_addr = le64(read_mem(pid, regs.rsp, 8))
                        regs.rax = y & MASK
                        regs.rsp += 8
                        regs.rip = ret_addr
                        setregs(pid, regs)
                        continue
                if emulate_qemu64_cpuid and hit_addr in (0x404a80, 0x404ba0):
                    ret_addr = le64(read_mem(pid, regs.rsp, 8))
                    regs.rax = 0 if hit_addr == 0x404a80 else qemu64_ext.get(regs.rdi & 0xffffffff, 0)
                    regs.rsp += 8
                    regs.rip = ret_addr
                    setregs(pid, regs)
                    continue
                regs.rip = hit_addr
                setregs(pid, regs)
                idx = regs.r15
                # The first argument is the six-lane VM state.  The stack
                # buffer passed as rsi is the generated JIT constant table.
                jit_state_addr = regs.r12
                if jit_inner_checks or jit_dump_indexes or jit_state_refs or jit_find_inputs:
                    op = regs.r14 & 0xffffffff
                    state = None
                    input_word = None
                    if jit_find_inputs or idx in jit_dump_indexes:
                        input_word = int.from_bytes(read_mem(pid, regs.r13, 4), "little")
                    if input_word in jit_find_inputs and jit_find_inputs[input_word] is None:
                        jit_find_inputs[input_word] = idx
                        print(f"jit_input_match {input_word:#x} idx {idx} op {op:#x}", file=sys.stderr)
                    if jit_state_refs:
                        state = read_mem(pid, jit_state_addr, 48)
                        hh = hashlib.sha256(state).hexdigest()[:32]
                        if hh in jit_state_refs and jit_state_refs[hh] is None:
                            jit_state_refs[hh] = (idx, op, state)
                    if idx in jit_dump_indexes:
                        if state is None:
                            state = read_mem(pid, jit_state_addr, 48)
                        print(f"jit_op {idx} input {input_word:#x} op {op:#x} r8 {regs.r8 & 0xffffffff:#x} r9 {regs.r9 & 0xffffffff:#x} rcx {regs.rcx & 0xffffffff:#x} h {hashlib.sha256(state).hexdigest()[:32]}", file=sys.stderr)
                    key = (idx, op)
                    if key in jit_inner_checks and jit_inner_checks[key] is None:
                        state = read_mem(pid, jit_state_addr, 48)
                        acc = read_mem(pid, 0x4a92d0, 8)
                        jit_inner_checks[key] = state + acc
                elif idx in checkpoints and checkpoints[idx] is None:
                    state = read_mem(pid, jit_state_addr, 48)
                    acc = read_mem(pid, 0x4a92d0, 8)
                    checkpoints[idx] = state + acc
                    if os.environ.get("STOP_AFTER_CHECKPOINTS") == "1" and all(v is not None for v in checkpoints.values()):
                        os.kill(pid, signal.SIGKILL)
                        break
                if idx in trace_tokens and 0 <= patch_pos < 12:
                    write_mem(pid, jit_state_addr + patch_pos * 4, trace_tokens[idx].to_bytes(4, "little"))
                if idx in trace_tokens and 0 <= patch_qword < 6:
                    write_mem(pid, jit_state_addr + patch_qword * 8, trace_tokens[idx].to_bytes(8, "little"))
                if idx in trace_tokens and patch_acc:
                    write_mem(pid, 0x4a92d0, trace_tokens[idx].to_bytes(4, "little"))
                if idx in trace_tokens and patch_acc_qword:
                    write_mem(pid, 0x4a92d0, trace_tokens[idx].to_bytes(8, "little"))
                bp_orig = breakpoints[hit_addr]
                ptrace(PTRACE_POKEDATA, pid, hit_addr, bp_orig)
                ptrace(PTRACE_SINGLESTEP := 9, pid, 0, 0)
                os.waitpid(pid, 0)
                ptrace(PTRACE_POKEDATA, pid, hit_addr, (bp_orig & ~0xff) | 0xcc)
                continue
            continue
        if not (sig & 0x80):
            continue
        regs = getregs(pid)
        if entering:
            nr = regs.orig_rax
            action = None
            if nr in (SYS_OPEN, SYS_OPENAT):
                path_addr = regs.rdi if nr == SYS_OPEN else regs.rsi
                path = read_cstr(pid, path_addr)
                if path in (b"/dev/chronicle", b"/dev/ttyS1"):
                    if path == b"/dev/chronicle":
                        install_bp()
                    action = ("ret", FD_CHRONICLE if path == b"/dev/chronicle" else FD_TTY)
                    regs.orig_rax = 39
                    setregs(pid, regs)
            elif nr == SYS_IOCTL and regs.rdi == FD_CHRONICLE:
                cmd, arg = regs.rsi, regs.rdx
                if cmd == 0x80289D52:
                    write_mem(pid, arg, module_hello(s, profile))
                elif cmd == 0xC0589D81:
                    inp = read_mem(pid, arg, 0x58)
                    write_mem(pid, arg, module_step(s, inp, module_trace_cb if module_trace_refs else None, module_trace_count))
                elif cmd == 0x80309DB6:
                    write_mem(pid, arg, b"".join(st64(x) for x in s))
                ioctl_count += 1
                action = ("ret", 0)
                regs.orig_rax = 39
                setregs(pid, regs)
            elif nr == SYS_READ and regs.rdi == FD_TTY:
                if live_sock is not None:
                    chunks = []
                    need = regs.rdx
                    while need:
                        c = live_sock.recv(need)
                        if not c:
                            break
                        chunks.append(c)
                        need -= len(c)
                    data = b"".join(chunks)
                else:
                    data = reads[read_idx]
                    read_idx += 1
                write_mem(pid, regs.rsi, data)
                action = ("ret", len(data))
                regs.orig_rax = 39
                setregs(pid, regs)
            elif nr == SYS_WRITE and regs.rdi == FD_TTY:
                data = read_mem(pid, regs.rsi, regs.rdx)
                writes.append(data)
                if live_sock is not None:
                    live_sock.sendall(data)
                action = ("ret", regs.rdx)
                regs.orig_rax = 39
                setregs(pid, regs)
            elif nr == SYS_CLOSE and regs.rdi in (FD_CHRONICLE, FD_TTY):
                action = ("ret", 0)
                regs.orig_rax = 39
                setregs(pid, regs)
            actions[pid] = action
        else:
            action = actions.get(pid)
            if action and action[0] == "ret":
                regs.rax = action[1]
                setregs(pid, regs)
        entering = not entering
    if module_trace_refs:
        for hh, hit in module_trace_refs.items():
            if hit:
                label, count, state = hit
                print(f"module_hit {hh} {label} {count} {state.hex()}", file=sys.stderr)
            else:
                print(f"module_miss {hh}", file=sys.stderr)
    for (idx, op), data in sorted(jit_inner_checks.items()):
        if data:
            print(f"jit_inner {idx} {op:#x} {data[:48].hex()} acc {data[48:].hex()}", file=sys.stderr)
        else:
            print(f"jit_inner {idx} {op:#x} missing", file=sys.stderr)
    for hh, hit in jit_state_refs.items():
        if hit:
            idx, op, state = hit
            print(f"jit_hit {hh} idx {idx} op {op:#x} {state.hex()}", file=sys.stderr)
        else:
            print(f"jit_miss {hh}", file=sys.stderr)
    return b"".join(writes), writes, checkpoints


if __name__ == "__main__":
    seed = bytes.fromhex(sys.argv[1]) if len(sys.argv) > 1 else bytes.fromhex("f3672b6fa1638ee95fa7c2c0befaafd4208503ad39fa059e28f020e2024df30c")
    profile = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    sock_path = os.environ.get("CHRONICLE_SOCK")
    live = None
    server = None
    if sock_path:
        live = socket.socket(socket.AF_UNIX)
        live.connect(sock_path)
    else:
        server_path = os.environ.get("CHRONICLE_REPLAY", "/tmp/chal_write.bin")
        server = open(server_path, "rb").read()
    raw_state = None
    if os.environ.get("FAULTLINE_STATE_HEX"):
        b = bytes.fromhex(os.environ["FAULTLINE_STATE_HEX"])
        raw_state = [le64(b[i * 8:i * 8 + 8]) for i in range(6)]
    stream, messages, checkpoints = run(seed, profile, server, live, raw_state)
    if live is not None:
        live.shutdown(socket.SHUT_WR)
        while live.recv(4096):
            pass
    print(stream.hex())
    print("messages", [len(m) for m in messages], file=sys.stderr)
    for idx, data in sorted(checkpoints.items()):
        if data:
            print(f"checkpoint {idx} {data[:48].hex()} acc {data[48:].hex()}", file=sys.stderr)
        else:
            print(f"checkpoint {idx} missing", file=sys.stderr)
