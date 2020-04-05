import angr
proj = angr.load_shellcode(b")\xd8", arch="x86")
state = proj.factory.blank_state() 
#state.solver.add(state.regs.eflags == 0x202)
#print(state.regs.eflags)

state.regs.eax = state.solver.BVV(0, 32)
state.regs.ebx = state.solver.BVV(1<<31, 32)
successor = state.step()[0]
print(successor.regs.eflags)