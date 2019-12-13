from esilsolve import ESILSolver
import r2pipe
import solver

ONE = solver.BitVecVal(1, 1)
ZERO = solver.BitVecVal(0, 1)

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
    r2p = r2pipe.open("tests/simplish", flags=["-2"])
    r2p.cmd("s sym.check; aei; aeim; aer rdi=12605")

    esilsolver = ESILSolver(r2p, debug=True, trace=False)
    #esilsolver.initVM()

    state = esilsolver.initState()
    state.setSymbolicRegister("rdi")
    rdi = state.registers["rdi"]
    esilsolver.run(target=0x00000668)
    #print(state.registers["zf"])
    #state.solver.add(solver.BV2Int(state.registers["zf"]) == 1)
    state.solver.add(state.registers["zf"] == 1)
    #state.solver.minimize(rdi)
    sat = state.solver.check()
    #print(state.solver)
    print(sat)
    m = state.solver.model()
    print(m.eval(rdi))
    #print(state.solver.statistics())

def test_newreg():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    esilsolver.parseExpression("1,rax,+=[8],rax,[8],1,+", state)
    print(state.stack)

def test_cond():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    esilsolver.parseExpression("rdx,?{,4,rbx,=,5,}{,1,2,rbx,=,},rbx,rax", state)
    print(state.stack)
    print(state.registers["rbx"])

def test_multi():
    r2p = r2pipe.open("tests/multibranch", flags=["-2"])
    r2p.cmd("aa; s sym.check; aei; aeim; aer rdi=22021")

    esilsolver = ESILSolver(r2p, debug=True, trace=False)
    #esilsolver.initVM()

    state = esilsolver.initState()
    state.setSymbolicRegister("rdi")
    #state.registers["rdi"] = solver.BitVecVal(0xdead, 64)
    rdi = state.registers["rdi"]

    esilsolver.run(target=0x0000066f)
    #print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    #sat = state.solver.check()
    #m = state.solver.model()
    #print(m.eval(rdi))

    esilsolver.run(target=0x0000069f)
    print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    #state.solver.minimize(rdi)
    #print(state.solver)
    print("solving")
    sat = state.solver.check()
    print(sat)

    m = state.solver.model()
    print(m.eval(rdi))

def test_multi_hook():
    r2p = r2pipe.open("tests/multibranch", flags=["-2"])
    r2p.cmd("aa; s sym.check; aei; aeim; aer rdi=22021")

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    #esilsolver.initVM()

    state = esilsolver.initState()
    state.setSymbolicRegister("rdi")
    rdi = state.registers["rdi"]
    state.solver.add(rdi >= 0)

    def success(instr, state):
        if instr["offset"] == 0x000006a1:
            sat = state.solver.check()
            m = state.solver.model()
            print("ARG1: %d" % m.eval(rdi).as_long())
            return True
        
        return False

    esilsolver.run(target=success, avoid=[0x000006a8])

def test_arm():
    r2p = r2pipe.open("ipa://tests/crackme-level0-symbols.ipa", flags=["-2"])
    r2p.cmd("aaa; s sym._validate; w 17492 @ 0x100000; aei; aeim; aer x0 = 0x100000")

    esilsolver = ESILSolver(r2p, debug=True, trace=False)
    state = esilsolver.states[0]
    esilsolver.run(state, target=0x100005ea4)

    print(state.stack)

if __name__ == "__main__":
    #test_cond()
    #test_sym()
    #test_mem()
    #test_flg()
    #test_run()
    #test_newreg()
    test_multi_hook()
    #test_arm()