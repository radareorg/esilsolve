from esilsolve import ESILSolver

buf_addr = 0x100000
buf_len = 16

esilsolver = ESILSolver("ipa://tests/crackme-level0-symbols.ipa", debug=False)
state = esilsolver.call_state("sym._validate")
state.registers["x0"] = buf_addr

#use r2pipe like normal in context of the app
validate = esilsolver.r2pipe.cmdj("pdj 1")[0]["offset"]
smt = esilsolver.smt # just z3 with some extras

# initialize symbolic bytes of solution
# and constrain them to be /[a-z ]/
b = [smt.BitVec("b%d" % x, 8) for x in range(buf_len)]
for x in b:
    state.solver.add(smt.Or(smt.And(x >= 0x61, x <= 0x7a), x == 0x20))

# concat the bytes and write the BV to memory 
code = smt.Concat(*b)
#state.constrain_bytes(b, "[a-z ]") # alternate way to constrain
state.memory[buf_addr] = b

# success hook callback
def success(instr, state):
    cs = smt.BV2Bytes(state.evaluate(code))
    # gives an answer with lots of spaces but it works
    print("CODE: '%s'" % cs.decode())

# set the hooks and run
esilsolver.register_hook(validate+0x210, success)
esilsolver.run(target=validate+0x210, avoid=[validate+0x218, validate+0x3c])