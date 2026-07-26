import angr, claripy
BIN='./target_obf'; BASE=0x400000
proj=angr.Project(BIN, main_opts={'base_addr':BASE}, auto_load_libs=False)
class Ret0(angr.SimProcedure):
 def run(self,*args): return claripy.BVV(0,self.state.arch.bits)
for sym in ['pthread_mutex_lock','pthread_mutex_unlock','_ZNSt6thread4joinEv','_ZNSt6thread15_M_start_threadESt10unique_ptrINS_6_StateESt14default_deleteIS1_EEPFvvE','_ZdlPv','_ZNSt6thread6_StateD2Ev','puts']:
 try: proj.hook_symbol(sym, Ret0())
 except Exception: pass
chars=b'abcdefghijklmnopqrstuvwxyz0123456789_'
flag_len=40
bs=[claripy.BVS(f'c{i}',8) for i in range(flag_len)]
flag=claripy.Concat(*bs, claripy.BVV(0,8))
st=proj.factory.blank_state(addr=BASE+0x256770)
st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
argv=0x700000; arg0=0x701000; arg1=0x702000
st.memory.store(arg0,b'./target_obf\0'); st.memory.store(arg1,flag)
st.memory.store(argv, claripy.BVV(arg0,64), endness=proj.arch.memory_endness)
st.memory.store(argv+8, claripy.BVV(arg1,64), endness=proj.arch.memory_endness)
st.regs.rdi=2; st.regs.rsi=argv
for i,ch in enumerate(b'DH{'): st.solver.add(bs[i]==ch)
st.solver.add(bs[39]==ord('}'))
for i in range(3,39): st.solver.add(claripy.Or(*[bs[i]==c for c in chars]))
sm=proj.factory.simgr(st)
sm.stashes['found']=[]
sm.stashes['avoid']=[]
find=BASE+0x1938cc; avoid=BASE+0x18f925
for step in range(20000):
 if sm.found: break
 sm.move(from_stash='active', to_stash='found', filter_func=lambda s: s.addr==find)
 sm.move(from_stash='active', to_stash='avoid', filter_func=lambda s: s.addr==avoid)
 if not sm.active: break
 if step%100==0: print('step',step,'active',len(sm.active),'addr',hex(sm.active[0].addr), flush=True)
 sm.step(num_inst=1)
 if len(sm.active)>16:
  sm.active=sm.active[:16]
print(sm)
if sm.found:
 s=sm.found[0].solver.eval(flag,cast_to=bytes).rstrip(b'\0'); print(s)
