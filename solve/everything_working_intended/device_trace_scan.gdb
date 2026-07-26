set pagination off
set confirm off
set disassembly-flavor intel

python
import hashlib

refs = {
    "0bd2c057e1faed1f1c1f46b26620d46d": "0413",
    "24b8d97e40768fc775e9b3efa6bc157e": "0755",
    "c50fbc34608ebc1cad20032a6a8ffd89": "1057",
    "9f733bd1cba3be1cae63602789a4f604": "1419",
    "1db9a93aaa2fecc36fcef1895b7b00f8": "1751",
    "17b6e72a8acb305afc74bb54b5b29de2": "2057",
    "21c97e30ca0d905cb3d17bc5e5c9b911": "2399",
}
hits = set()

class Scan48(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, internal=False)
        self.silent = True

    def stop(self):
        frame = gdb.newest_frame()
        rbp = int(frame.read_register("rbp"))
        rip = int(frame.read_register("rip"))
        inferior = gdb.selected_inferior()
        base = rbp - 0x3c8
        blob = inferior.read_memory(base, 0x3c8).tobytes()
        for off in range(0, len(blob) - 47):
            h = hashlib.sha256(blob[off:off + 48]).hexdigest()[:32]
            if h in refs and h not in hits:
                hits.add(h)
                print(f"trace_hit {refs[h]} rip={rip:#x} stack_off=-{rbp - (base + off):#x} state={blob[off:off + 48].hex()}")
        return False

for addr in (
    0x4024b0, 0x4024ed, 0x4024fd, 0x402570, 0x4025b8,
    0x4025f0, 0x40260e, 0x40262c, 0x402657, 0x402682,
    0x4026a8, 0x4026c6, 0x402742, 0x40276d, 0x4027b2,
):
    Scan48(f"*{addr:#x}")
end

run --socket /tmp/faultline-device-scan.sock
