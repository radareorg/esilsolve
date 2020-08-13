from esilsolve import ESILSolver
import z3 

buf_addr = 0x100000
buf_len = 16

esilsolver = ESILSolver("ipa://test/tests/crackme-level0-symbols.ipa", debug=False)
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
esilsolver.run()