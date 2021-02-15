from esilsolve import ESILSolver

esilsolver = ESILSolver("r100", sim=False)
flag = esilsolver.z3.BitVec("flag", 12*8)
state = esilsolver.call_state(0x004006fd, args=[[flag]])
end = esilsolver.run(target=0x004007a1, avoid=[0x00400790])
print("FLAG: %s " % end.evaluate_string(flag))