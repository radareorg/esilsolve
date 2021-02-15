from esilsolve import ESILSolver
import z3

esilsolver = ESILSolver("baby-re", lazy=True, sim=False)
esilsolver.r2pipe.cmd("oo+; wa ret @ sym.imp.printf")
esilsolver.r2pipe.cmd("wa ret @ sym.imp.fflush")
esilsolver.r2pipe.cmd("wa ret @ sym.imp.__isoc99_scanf")

state = esilsolver.call_state("main")
esilsolver.context["ints"] = []

def scanf(state, fmt_ptr, int_ptr):
    inputs = esilsolver.context["ints"]
    inp = z3.BitVec("int%d" % len(inputs), 32)
    inputs.append(inp)
    state.memory[int_ptr.as_long()] = inp
    return 1

esilsolver.register_sim("sym.imp.__isoc99_scanf", scanf)
state = esilsolver.run(target=0x004028e9, avoid=[0x00402941])

chars = ""
for inp in esilsolver.context["ints"]:
    chars += chr(state.evaluate(inp).as_long() & 0xff)

print("FLAG: %s" % chars)

