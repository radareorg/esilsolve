from esilsolve import ESILSolver

# start the ESILSolver instance
# and init state with r2 symbol for check function
esilsolver = ESILSolver("test/tests/floatarm", debug=True)
state = esilsolver.call_state("main")

# make rdi (arg1) symbolic
state.set_symbolic_register("x0")
#state.registers["x0"] = 2
arg = state.registers["x0"]

# set targets and avoided addresses
# state will contain a state at the target pc addr
state = esilsolver.run(target=0x648, avoid=[0x650])
print("ARG1: %d " % state.evaluate(arg).as_long())
