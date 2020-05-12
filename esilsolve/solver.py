from z3 import *
import binascii

set_param(auto_config=False)
#solver.Z3_DEBUG = False

def EvalMax(solver, sym, n=16):
    solutions = []

    while len(solutions) < n:

        solver.push()
        for sol in solutions:
            solver.add(sym != sol)

        satisfiable = solver.check()

        if satisfiable == sat:
            m = solver.model()
            solutions.append(m.eval(sym, model_completion=True))

        else:
            solver.pop()
            break

        solver.pop()

    return solutions

def BV2Bytes(bv):
    return binascii.unhexlify("%x"%bv.as_long())[::-1]