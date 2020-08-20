from esilsolve import ESILSolver
import z3

# load the binary and use lazy solving 
esilsolver = ESILSolver("unbreakable", lazy=True)
state = esilsolver.call_state(0x004005bd)

# initialize the symbolic flag value
flag = z3.BitVec("flag", (0x33)*8)
state.constrain_bytes(flag, b"CTF{")
state.memory[0x6042c0] = flag

# run until it reaches the success state, avoiding failure
state = esilsolver.run(target=0x00400830, avoid=[0x00400850])
print("FLAG: %s " % state.evaluate_string(flag))
