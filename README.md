## <img src="https://raw.githubusercontent.com/aemmitt-ns/esilsolve/master/raphi.svg" alt="logo" width="200"/> ESILSolve - A python symbolic execution framework using r2 and ESIL

ESILSolve uses the z3 theorem prover and r2's ESIL intermediate representation to symbolically execute code. 

ESILSolve supports the same architectures as ESIL, including x86, amd64, arm, aarch64 and more (6502, 8051, GameBoy...). This project is a work in progress.

### Example Usage

```python
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

```

ESILSolve also easily works with ipa and apk files since they are supported by r2. 

### IPA CrackMe Example

```python
from esilsolve import ESILSolver
import z3 

buf_addr = 0x100000
buf_len = 16

esilsolver = ESILSolver("ipa://tests/crackme-level0-symbols.ipa", debug=False)
state = esilsolver.call_state("sym._validate")
state.registers["x0"] = buf_addr

#use r2pipe like normal in context of the app
validate = esilsolver.r2pipe.cmdj("pdj 1")[0]["offset"]

# initialize symbolic bytes of solution
# and constrain them to be /[a-z ]/
b = [z3.BitVec("b%d" % x, 8) for x in range(buf_len)]
state.constrain_bytes(b, "[a-z ]") 

# concat the bytes and write them to memory 
code = z3.Concat(*b)
state.memory[buf_addr] = code

# success hook callback
def success(state):
    cs = state.evaluate_buffer(code)
    # gives an answer with lots of spaces but it works
    print("CODE: '%s'" % cs.decode())
    esilsolver.terminate()

# set the hooks and run
esilsolver.register_hook(validate+0x210, success)
esilsolver.run(avoid=[validate+0x218, validate+0x3c])
```
