set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off

python
import gdb

BASE = 0x555555554000
check_rbp = None

class CheckEntry(gdb.Breakpoint):
    def stop(self):
        global check_rbp
        check_rbp = int(gdb.parse_and_eval('$rbp'))
        return False

class SingleBit(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__('*%#x' % addr, internal=True)
        self.addr = addr
    def stop(self):
        if check_rbp is None or int(gdb.parse_and_eval('$rbp')) != check_rbp:
            return False
        rax = int(gdb.parse_and_eval('$rax')) & ((1 << 64) - 1)
        if rax and not (rax & (rax - 1)):
            rcx = int(gdb.parse_and_eval('$rcx')) & 0xff
            gdb.write('BT pc=%#x bitset=%#x index=%u\n' % (self.addr - BASE, rax, rcx))
        return False

CheckEntry('*%#x' % (BASE + 0x2076cb), internal=True)
blob = open('target_obf', 'rb').read()
for offset in range(len(blob) - 4):
    if blob[offset:offset + 4] == b'\x48\x0f\xa3\xc8':
        vaddr = offset + 0x1000
        if 0x9f380 <= vaddr < 0x267780:
            SingleBit(BASE + vaddr)
end
