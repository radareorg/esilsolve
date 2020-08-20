from esilsolve import ESILSolver
import r2pipe
import z3

r2p = r2pipe.open("r200", flags=["-d", "-2"])
r2p.cmd("wa ret @ sym.imp.ptrace") # nop antidebug
r2p.cmd("db 0x004008fa; dc;") # setup the linked list 

esilsolver = ESILSolver(r2p)

state = esilsolver.call_state(0x0040074d)

addr = 0x1000000
state.registers["rdi"] = addr
flag = z3.BitVec("flag", 6*8)
state.memory[addr] = flag
state.constrain_bytes(flag, "[sort]") # cheating

# this one takes a while, even after cheating
state = esilsolver.run(target=0x00400843, avoid=[0x00400832])

if state != None:
    print("FLAG: %s " % state.evaluate_buffer(flag).decode())
else:
    print("Could not reach target")
