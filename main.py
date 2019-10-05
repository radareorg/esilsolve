from esilsolve import ESILSolver

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
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    esilsolver.parseExpression("1,1,==,$z,zf,:=,zf", state)

    print(state.stack)
    print(state.popAndEval())

if __name__ == "__main__":
    test_sym()
    test_mem()
    test_flg()