from esilsolve import ESILSolver
import z3

esilsolver = ESILSolver("test/tests/r100", init=True)
state = esilsolver.call_state(0x004006fd)

addr = 0x1000000
state.registers["rdi"] = addr
flag = z3.BitVec("flag", 12*8)
state.memory[addr] = flag

state = esilsolver.run(target=0x004007a1, avoid=[0x00400790])
print("FLAG: %s " % state.evaluate_buffer(flag).decode())
