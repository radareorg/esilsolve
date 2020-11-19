from esilsolve import ESILSolver
import z3

esilsolver = ESILSolver("test/tests/validate", pcode=True)
state = esilsolver.call_state(0x1760)

addr = 0x100000
state.registers["r0"] = addr
flag = z3.BitVec("flag", 16*8)
state.memory[addr] = flag 

state = esilsolver.run(target=0x00001840, avoid=[0x00001854])
flag_str = state.evaluate_buffer(flag).replace(b"\x00", b"")
print("FLAG: %s " % flag_str)