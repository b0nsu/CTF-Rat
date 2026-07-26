import angr, claripy

BIN='./target_obf'
BASE=0x400000
proj=angr.Project(BIN, main_opts={'base_addr':BASE}, auto_load_libs=False)

class Ret0(angr.SimProcedure):
    def run(self, *args): return claripy.BVV(0, self.state.arch.bits)
class Memset(angr.SimProcedure):
    def run(self, dst, c, n):
        self.state.memory.store(dst, claripy.BVV(0,8).reversed if False else claripy.BVV(0,8), size=n)
        return dst
# hook imports that are irrelevant/noisy
for sym in ['pthread_mutex_lock','pthread_mutex_unlock','_ZNSt6thread4joinEv','_ZNSt6thread15_M_start_threadESt10unique_ptrINS_6_StateESt14default_deleteIS1_EEPFvvE','_ZdlPv','_ZNSt6thread6_StateD2Ev']:
    try: proj.hook_symbol(sym, Ret0())
    except Exception: pass
# puts: return 0, but find by addr before call
try: proj.hook_symbol('puts', Ret0())
except Exception: pass

chars=b'abcdefghijklmnopqrstuvwxyz0123456789_'
flag_len=40
bs=[claripy.BVS(f'c{i}',8) for i in range(flag_len)]
arg=claripy.Concat(*bs, claripy.BVV(0,8))
st=proj.factory.full_init_state(args=[BIN,arg])
st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
known=b'DH{'
for i,ch in enumerate(known): st.solver.add(bs[i]==ch)
st.solver.add(bs[39]==ord('}'))
for i in range(3,39): st.solver.add(claripy.Or(*[bs[i]==c for c in chars]))
sm=proj.factory.simgr(st)
find=BASE+0x1938cc
avoid=BASE+0x18f925
print('find',hex(find),'avoid',hex(avoid))
sm.explore(find=find, avoid=avoid, n=1)
print(sm)
if sm.found:
    s=sm.found[0].solver.eval(arg, cast_to=bytes).rstrip(b'\0')
    print(s)
