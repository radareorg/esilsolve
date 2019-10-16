from esilsolve import ESILSolver
import r2pipe
import solver

def test_sym():
    esilsolver = ESILSolver(debug=True)
    state = esilsolver.states[0]
    state.setSymbolicRegister("rax")
    esilsolver.parseExpression("1,rax,+,rbx,=,2,bx,<<,rbx,=", state)
    #esilsolver.constrainRegister("rbx", 277)
    state.solver.add(state.registers["rbx"] > 277)
    state.solver.add(state.registers["bh"] % 2 == 0)

    #print(esilsolver.stack)
    #print(esilsolver.evaluateRegister("ah"))
    print(state.evaluateRegister("rax")) 

def test_mem():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    #esilsolver.context["memory"].write(0, [0xbe, 0xba, 0xfe, 0xca])
    #esilsolver.r2api.write(0, 0xcafebabe)
    state.setSymbolicRegister("rbx")
    esilsolver.parseExpression("7,rcx,=,rcx,0,+=[8],0,[8],rbx,+,rcx,=", state)
    state.solver.add(state.registers["rcx"] > 0xcafed00d)

    print(state.stack)
    print(state.evaluateRegister("rbx")) 

def test_flg():
    esilsolver = ESILSolver(debug=True)
    state = esilsolver.states[0]
    #esilsolver.parseExpression("1,1,==,$z,zf,:=,zf", state)
    esilsolver.parseExpression("2,0x4,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,$s,sf,:=,$o,of,:=", state)
    print(state.stack)
    #print(state.popAndEval())

def test_run():
    r2p = r2pipe.open("tests/simplish")
    r2p.cmd("aaa; s sym.check; aei; aeim")

    esilsolver = ESILSolver(r2p, debug=False)
    #esilsolver.initVM()

    state = esilsolver.states[0]
    state.setSymbolicRegister("rdi")
    rdi = state.registers["rdi"]
    esilsolver.run(state, target=0x00000668)
    print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    state.solver.minimize(rdi)
    sat = state.solver.check()
    print(sat)
    m = state.solver.model()
    print(m.eval(rdi))

def test_newreg():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    esilsolver.parseExpression("1,rax,+=[8],rax,[8],1,+", state)
    print(state.stack)

def test_multi():
    r2p = r2pipe.open("tests/multibranch")
    r2p.cmd("aaa; s sym.check; aei; aeim; aer rdi=0xdead")

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    #esilsolver.initVM()

    state = esilsolver.states[0]
    state.setSymbolicRegister("rdi")
    #state.registers["rdi"] = solver.BitVecVal(0xdead, 64)
    rdi = state.registers["rdi"]

    esilsolver.run(state, target=0x0000066f)
    print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    #sat = state.solver.check()
    #m = state.solver.model()
    #print(m.eval(rdi))

    esilsolver.run(state, target=0x0000069f)
    #print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    state.solver.minimize(rdi)
    #print(state.solver)
    sat = state.solver.check()
    print(sat)

    m = state.solver.model()
    print(m.eval(rdi))

if __name__ == "__main__":
    #test_sym()
    #test_mem()
    #test_flg()
    #test_run()
    #test_newreg()
    test_multi()