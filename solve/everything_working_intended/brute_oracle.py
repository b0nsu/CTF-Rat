#!/usr/bin/env python3
import argparse
import contextlib
import io
import multiprocessing as mp
import os
import socket
import subprocess
import sys
import tempfile
import time

import guest_ptrace_emu as emu


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CHAL = "f3672b6fa1638ee95fa7c2c0befaafd4208503ad39fa059e28f020e2024df30c"
CAL = "51ec381a71a5c25f7f7877bba230bd56a9dabaf70d9e34c369f0f6c2a5a19678"
DEVICE = os.path.join(ROOT, "solve/everything_working_intended/faultline/chronicle_device")


def wait_sock(path, proc):
    for _ in range(200):
        if os.path.exists(path):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.01)
    return False


def run_candidate(item):
    label, patch_env = item
    fd, sock_path = tempfile.mkstemp(prefix="faultline-oracle-", suffix=".sock")
    os.close(fd)
    os.unlink(sock_path)
    env = os.environ.copy()
    env.pop("TRACE_CHECKPOINTS", None)
    env.pop("TRACE_TOKENS", None)
    env.pop("TRACE_PATCH_DWORD", None)
    env.pop("TRACE_PATCH_ACC", None)
    env.pop("PATCH_KEY0_HEX", None)
    env.pop("PATCH_KEY1_HEX", None)
    env.update(patch_env)
    proc = subprocess.Popen(
        [DEVICE, "--socket", sock_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    try:
        if not wait_sock(sock_path, proc):
            out = proc.communicate(timeout=1)[0].decode("latin1", "replace")
            return label, "NO_SOCKET", out
        s = socket.socket(socket.AF_UNIX)
        s.connect(sock_path)
        old_env = os.environ.copy()
        os.environ.clear()
        os.environ.update(env)
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                emu.run(bytes.fromhex(CHAL), 1, live_sock=s)
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_WR)
            while s.recv(4096):
                pass
        finally:
            s.close()
            os.environ.clear()
            os.environ.update(old_env)
        out = proc.communicate(timeout=2)[0].decode("latin1", "replace")
        if proc.returncode == 0:
            status = "OK"
        elif "transcript rejected" in out:
            status = "REJECT"
        else:
            status = f"EXIT{proc.returncode}"
        return label, status, out.strip()
    except Exception as exc:
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=1)
        return label, "ERR", repr(exc)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(sock_path)


def bitflip_candidates(which_key):
    base = bytearray.fromhex(CHAL if which_key == 1 else CAL)
    name = f"PATCH_KEY{which_key}_HEX"
    for bit in range(len(base) * 8):
        b = bytearray(base)
        b[bit // 8] ^= 1 << (bit % 8)
        yield f"key{which_key}_bit_{bit}", {name: b.hex()}


def stuck_candidates(which_key):
    base = bytearray.fromhex(CHAL if which_key == 1 else CAL)
    name = f"PATCH_KEY{which_key}_HEX"
    for i in range(len(base)):
        for val in (0, 0xff):
            if base[i] == val:
                continue
            b = bytearray(base)
            b[i] = val
            yield f"key{which_key}_byte_{i:02x}_{val:02x}", {name: b.hex()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["key1-bits", "key1-stuck", "key0-bits", "key0-stuck"])
    ap.add_argument("-j", "--jobs", type=int, default=4)
    args = ap.parse_args()
    if args.mode == "key1-bits":
        candidates = list(bitflip_candidates(1))
    elif args.mode == "key1-stuck":
        candidates = list(stuck_candidates(1))
    elif args.mode == "key0-bits":
        candidates = list(bitflip_candidates(0))
    else:
        candidates = list(stuck_candidates(0))
    print(f"testing {len(candidates)} candidates for {args.mode}", flush=True)
    hits = []
    with mp.Pool(args.jobs) as pool:
        for label, status, out in pool.imap_unordered(run_candidate, candidates):
            if status not in ("REJECT", "EXIT2"):
                hits.append((label, status, out))
                print(f"[{status}] {label}: {out}", flush=True)
    print(f"done hits={len(hits)}")
    for hit in hits:
        print(repr(hit))
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
