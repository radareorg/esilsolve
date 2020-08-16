from esilsolve import ESILSolver
import z3

esilsolver = ESILSolver("test/tests/unbreakable", lazy=True)
state = esilsolver.call_state(0x004005bd)

flag = z3.BitVec("flag", (0x33)*8)
for i in range(4):
    state.constrain(z3.Extract(7+i*8, i*8, flag) == ord("CTF{"[i]))

addr = 0x6042c0
state.memory[addr] = flag

state = esilsolver.run(target=0x00400830, avoid=[0x00400850])
print("FLAG: %s " % state.evaluate_buffer(flag).decode())
