#!/usr/bin/env python3
"""Run profile-field variants through the supplied local QEMU/device setup."""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FAULT = ROOT / "faultline"
CAL_IMG = (FAULT / "esp.calibration.img").read_bytes()
CHAL_IMG = (FAULT / "esp.challenge.img").read_bytes()
BOOT_OFF = 0x36000
BOOT_LEN = 5373952
FIELDS = (0x556845, 0x556856, 0x55686B)
CAL_EFI = (ROOT / "extracted/esp.calibration/EFI/FAULTL~1/FAULTL~1.EFI").read_bytes()
CHAL_EFI = (ROOT / "extracted/esp.challenge/EFI/FAULTL~1/FAULTL~1.EFI").read_bytes()
EFI_OFF = CAL_IMG.find(CAL_EFI)
assert EFI_OFF >= 0 and CHAL_IMG.find(CHAL_EFI) == EFI_OFF


def wait_socket(path, proc):
    for _ in range(200):
        if path.exists():
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.01)
    return False


def run_variant(bits):
    # bit 0 chooses calibration BOOTX64; the other bits choose each firmware
    # profile byte from the calibration image.
    image = bytearray(CHAL_IMG)
    if bits & 1:
        image[BOOT_OFF:BOOT_OFF + BOOT_LEN] = CAL_IMG[BOOT_OFF:BOOT_OFF + BOOT_LEN]
    for i, off in enumerate(FIELDS):
        if bits & (2 << i):
            image[off] = CAL_IMG[off]
    if bits & 0x10:
        image[EFI_OFF:EFI_OFF + len(CAL_EFI)] = CAL_EFI
    with tempfile.TemporaryDirectory(prefix="faultline-profile-") as temp:
        temp = Path(temp)
        image_path = temp / "esp.img"
        vars_path = temp / "vars.fd"
        sock_path = temp / "chron.sock"
        image_path.write_bytes(image)
        shutil.copyfile(FAULT / "OVMF_VARS.fd", vars_path)
        device = subprocess.Popen(
            [FAULT / "chronicle_device", "--socket", sock_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            if not wait_socket(sock_path, device):
                return "device-no-socket"
            qemu = subprocess.run(
                ["qemu-system-x86_64", "-machine", "pc,accel=tcg", "-cpu", "qemu64", "-m", "512M", "-smp", "1",
                 "-drive", f"if=pflash,format=raw,readonly=on,file={FAULT / 'OVMF_CODE.fd'}",
                 "-drive", f"if=pflash,format=raw,file={vars_path}",
                 "-drive", f"if=virtio,format=raw,readonly=on,file={image_path}",
                 "-display", "none", "-serial", "none",
                 "-chardev", f"socket,id=chron,path={sock_path}", "-serial", "chardev:chron",
                 "-no-reboot", "-net", "none"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
            qemu_status = f"qemu={qemu.returncode}"
        except subprocess.TimeoutExpired:
            qemu_status = "qemu=timeout"
        finally:
            if device.poll() is None:
                device.terminate()
            try:
                out, _ = device.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                device.kill()
                out, _ = device.communicate()
        return f"{qemu_status} device={device.returncode} {out.strip()}"


def main():
    wanted = [int(x, 0) for x in sys.argv[1:]] or list(range(16))
    for bits in wanted:
        print(f"{bits:02x} {run_variant(bits)}", flush=True)


if __name__ == "__main__":
    main()
