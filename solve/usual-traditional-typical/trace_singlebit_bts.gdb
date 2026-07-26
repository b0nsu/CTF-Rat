set debuginfod enabled off
set disable-randomization on
set pagination off
set confirm off
set print thread-events off
set logging file singlebit_bts.log
set logging overwrite on
set logging enabled on

python
import gdb

BASE = 0x555555554000
CHECK_ENTRY = BASE + 0x2076cb
CHECK_DONE = BASE + 0x1614a6
check_rbp = None

class CheckEntry(gdb.Breakpoint):
    def stop(self):
        global check_rbp
        check_rbp = int(gdb.parse_and_eval('$rbp'))
        gdb.write('CHECK_RBP=%#x\n' % check_rbp)
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

class Done(gdb.Breakpoint):
    def stop(self):
        gdb.write('DONE\n')
        gdb.execute('quit')
        return False

CheckEntry('*%#x' % CHECK_ENTRY, internal=True)
Done('*%#x' % CHECK_DONE, internal=True)
blob = open('target_obf', 'rb').read()
# The x86-64 checker consistently uses "bt rax, rcx" for membership tests.
for offset in range(len(blob) - 4):
    if blob[offset:offset + 4] == b'\x48\x0f\xa3\xc8':
        # RX segment: file offset 0x9f380 maps at virtual address 0xa0380.
        vaddr = offset + 0x1000
        if 0x9f380 <= vaddr < 0x267780:
            SingleBit(BASE + vaddr)
end

run DH{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}
