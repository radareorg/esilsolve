from esilsolve import ESILSolver

esilsolver = ESILSolver("r200", lazy=True)
state = esilsolver.call_state("main")
flag = esilsolver.z3.BitVec("flag", 6*8)
state.write_stdin(flag)

state = esilsolver.run(0x00400843,
    avoid=[0x00400832], merge=[0x004007fd])

print("FLAG:", state.evaluate_string(flag))