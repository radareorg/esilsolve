from esilsolve import ESILSolver

# start the ESILSolver instance
# and init state with r2 symbol for check function
esilsolver = ESILSolver("test/tests/float", debug=True, pcode=True)
state = esilsolver.call_state("main")

# make rdi (arg1) symbolic
state.set_symbolic_register("rdi")
#state.registers["rdi"] = 2
rdi = state.registers["rdi"]

# set targets and avoided addresses
# state will contain a state at the target pc addr
state = esilsolver.run(target=0x63a, avoid=[0x641])
print("ARG1: %d " % state.evaluate(rdi).as_long())
