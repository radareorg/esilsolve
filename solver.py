from z3 import *

set_param(auto_config=False)
#solver.Z3_DEBUG = False

def eval_max(solver, sym, n=16):
    solutions = []

    while len(solutions) < n:

        solver.push()
        for sol in solutions:
            solver.add(sym != sol)

        satisfiable = solver.check()

        if satisfiable == sat:
            m = solver.model()
            solutions.append(m.eval(sym))

        else:
            solver.pop()
            break

        solver.pop()

    return solutions