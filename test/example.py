from esilsolve import ESILSolver

# start the ESILSolver instance
# and init state with r2 symbol for check function
esilsolver = ESILSolver("test/tests/multibranch")
state = esilsolver.call_state("sym.check")

# make rdi (arg1) symbolic
state.set_symbolic_register("rdi")
rdi = state.registers["rdi"]

# set targets and avoided addresses
# state will contain a state at the target pc addr
state = esilsolver.run(target=0x6a1, avoid=[0x6a8])
print("ARG1: %d " % state.evaluate(rdi).as_long())
