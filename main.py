from esilsolve import ESILSolver
import r2pipe

def test_sym():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    state.setSymbolicRegister("rax")
    esilsolver.parseExpression("1,rax,+,rbx,=,2,bx,<<,rbx,=", state)
    #esilsolver.constrainRegister("rbx", 277)
    state.solver.add(state.registers["rbx"] > 277)
    state.solver.add(state.registers["bh"] % 2 == 0)

    #print(esilsolver.stack)
    #print(esilsolver.evaluateRegister("ah"))
    print(state.evaluateRegister("rax", "min")) 

def test_mem():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    #esilsolver.context["memory"].write(0, [0xbe, 0xba, 0xfe, 0xca])
    #esilsolver.r2api.write(0, 0xcafebabe)
    state.setSymbolicRegister("rbx")
    esilsolver.parseExpression("rbx,0,=[8],0,[8],rbx,+,rcx,=", state)
    state.solver.add(state.registers["rcx"] > 0xcafed00d)

    print(state.stack)
    print(state.evaluateRegister("rbx")) 

def test_flg():
    esilsolver = ESILSolver(debug=True)
    state = esilsolver.states[0]
    #esilsolver.parseExpression("1,1,==,$z,zf,:=,zf", state)
    esilsolver.parseExpression("2,0x4,rbp,-,[4],==,$z,zf,:=,32,$b,cf,:=,$p,pf,:=,$s,sf,:=,$o,of,:=", state)
    print(state.stack)
    print(state.popAndEval())

def test_run():
    r2p = r2pipe.open("tests/simplish")
    r2p.cmd("aaa; s sym.check; aei; aeim")

    esilsolver = ESILSolver(r2p, debug=True)
    #esilsolver.initVM()

    state = esilsolver.states[0]
    state.setSymbolicRegister("rdi")
    rdi = state.registers["rdi"]
    esilsolver.run(state, target=0x00000668)
    print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    sat = state.solver.check()
    print(sat)
    m = state.solver.model()
    print(m.eval(rdi))

if __name__ == "__main__":
    #test_sym()
    #test_mem()
    #test_flg()
    test_run()