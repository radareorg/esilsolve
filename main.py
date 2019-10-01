from esilsolve import ESILSolver

def test_sym():
    esilsolver = ESILSolver()
    esilsolver.setSymbolicRegister("rax")
    esilsolver.parseExpression("1,rax,+,rbx,=,1,?{1,rbx,+=},2,bx,<<,rbx,=")
    #esilsolver.constrainRegister("rbx", 277)
    esilsolver.solver.add(esilsolver.registers["rbx"] > 277)
    esilsolver.solver.add(esilsolver.registers["bh"] % 2 == 0)

    #print(esilsolver.stack)
    #print(esilsolver.evaluateRegister("ah"))
    print(esilsolver.evaluateRegister("rax", "min")) 

def test_mem():
    esilsolver = ESILSolver()
    #esilsolver.context["memory"].write(0, [0xbe, 0xba, 0xfe, 0xca])
    #esilsolver.r2api.write(0, 0xcafebabe)
    esilsolver.setSymbolicRegister("rbx")
    esilsolver.parseExpression("rbx,0,=[8],0,[8],rbx,+,rcx,=")
    esilsolver.solver.add(esilsolver.registers["rcx"] > 0xcafed00d)

    print(esilsolver.stack)
    print(esilsolver.evaluateRegister("rbx")) 

if __name__ == "__main__":
    test_sym()
    test_mem()