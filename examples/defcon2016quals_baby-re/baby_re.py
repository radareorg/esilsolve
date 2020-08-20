from esilsolve import ESILSolver, ESILSim
import r2pipe
import z3

esilsolver = ESILSolver("baby-re", lazy=True)
esilsolver.r2pipe.cmd("oo+; wa ret @ sym.imp.printf")
esilsolver.r2pipe.cmd("wa ret @ sym.imp.fflush")
esilsolver.r2pipe.cmd("wa ret @ sym.imp.__isoc99_scanf")

state = esilsolver.call_state("main")
esilsolver.context["ints"] = []

def scanf_hook(state):
    inputs = esilsolver.context["ints"]
    inp = z3.BitVec("int%d" % len(inputs), 32)
    inputs.append(inp)
    state.memory[state.registers["rsi"].as_long()] = inp

esilsolver.register_hook(0x004005b0, scanf_hook)
state = esilsolver.run(target=0x004028e9, avoid=[0x00402941])

chars = []
for inp in esilsolver.context["ints"]:
    chars.append(chr(state.evaluate(inp).as_long() & 0xff))

print("FLAG: %s" % "".join(chars))

