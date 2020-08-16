from esilsolve import ESILSolver
import r2pipe
import z3

esilsolver = ESILSolver("test/tests/ais3_crackme")
state = esilsolver.call_state("sym.verify")

addr = 0x1000000
state.registers["rdi"] = addr
flag = z3.BitVec("flag", 24*8)

state.memory[addr] = flag 

def check(state):
    state.constrain(state.registers["zf"] == 1)
    if state.is_sat():
        flag_str = state.evaluate_buffer(flag).decode()
        print("FLAG: %s " % flag_str)
        esilsolver.terminate()

esilsolver.register_hook(0x004005bd, check)
state = esilsolver.run()

