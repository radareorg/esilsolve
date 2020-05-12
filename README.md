# ESILSolve - A python symbolic execution framework using r2 and ESIL

ESILSolve uses the z3 theorem prover and r2's ESIL intermediate representation to symbolically execute code. 

ESILSolve supports the same architectures as ESIL, including x86, amd64, arm, aarch64 and more. This project is a work in progress.

Example Usage

```python
from esilsolve import ESILSolver

# start the ESILSolver instance
# and init state with r2 symbol for check function
esilsolver = ESILSolver("tests/multibranch", debug=False)
state = esilsolver.call_state("sym.check")

# make rdi (arg1) symbolic
state.set_symbolic_register("rdi")
rdi = state.registers["rdi"]

# hook callback
def success(instr, state):
    print("ARG1: %d" % state.evaluate(rdi).as_long())

# hook any address to manipulate states
# and set targets and avoided addresses
esilsolver.register_hook(0x6a1, success)
esilsolver.run(target=0x6a1, avoid=[0x6a8])
```