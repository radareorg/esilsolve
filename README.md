## ESILSolve - A python symbolic execution framework using r2 and ESIL

ESILSolve uses the z3 theorem prover and r2's ESIL intermediate representation to symbolically execute code. 

ESILSolve supports the same architectures as ESIL, including x86, amd64, arm, aarch64 and more. This project is a work in progress.

### Example Usage

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

ESILSolve also easily works with ipa and apk files since they are supported by r2. 

### IPA CrackMe Example

```python
from esilsolve import ESILSolver
import esilsolve.solver as solver # just z3 with some extras
import r2pipe

validate = 0
var_addr = 0x100000
buf_len = 16

# start r2pipe, set arg1, and get _validate address
r2p = r2pipe.open("ipa://tests/crackme-level0-symbols.ipa", flags=["-2"])
r2p.cmd("s sym._validate; aei; aeim; aer x0 = %d;" % var_addr)
validate = r2p.cmdj("pdj 1")[0]["offset"]

esilsolver = ESILSolver(r2p, debug=False)
state = esilsolver.init_state()

# initialize symbolic bytes of solution
# and constrain them to be /[a-z ]/
b = [solver.BitVec("b%d" % x, 8) for x in range(buf_len)]
for x in range(buf_len):
    state.solver.add(solver.Or(solver.And(b[x] >= 0x61, b[x] <= 0x7a), b[x] == 0x20))

# concat the bytes and write the BV to memory
code = solver.Concat(*b)
state.memory.write_bv(var_addr, code, buf_len)

# success hook callback
def success(instr, state):
    c = state.evaluate(code)
    cs = solver.BV2Bytes(c)
    # this gives an answer with lots of spaces but it works
    print("CODE: '%s'" % cs.decode())

# set the hooks and run
esilsolver.register_hook(validate+0x210, success)
esilsolver.run(target=validate+0x210, avoid=[validate+0x218, validate+0x3c])
```