from esilsolve import ESILSolver
import r2pipe
import z3
import binascii

def test_sym():
    esilsolver = ESILSolver(debug=True)
    state = esilsolver.states[0]
    state.set_symbolic_register("rax")
    esilsolver.parse_expression("1,rax,+,rbx,=,2,bx,<<,rbx,=", state)
    #esilsolver.constrainRegister("rbx", 277)
    state.solver.add(state.registers["rbx"] > 277)
    state.solver.add(state.registers["bh"] % 2 == 0)

    #print(esilsolver.stack)
    #print(esilsolver.evaluateRegister("ah"))
    print(state.evaluate_register("rax")) 

def test_mem():
    esilsolver = ESILSolver()
    state = esilsolver.init_state()
    #esilsolver.context["memory"].write(0, [0xbe, 0xba, 0xfe, 0xca])
    #esilsolver.r2api.write(0, 0xcafebabe)
    state.set_symbolic_register("rbx")
    esilsolver.parse_expression("7,rcx,=,rcx,0,+=[8],0,[8],rbx,+,rcx,=", state)
    state.solver.add(state.registers["rcx"] > 0xcafed00d)

    print(state.stack)
    print(state.evaluate_register("rbx")) 

def test_flg():
    esilsolver = ESILSolver(debug=True, trace=True)
    state = esilsolver.init_state()
    #esilsolver.parseExpression("1,1,==,$z,zf,:=,zf", state)
    state.proc.parse_expression("2147483648,ebx,=,2164261373,eax,=,ebx,eax,-=,31,$o,of,:=,31,$s,sf,:=,$z,zf,:=,$p,pf,:=,32,$b,cf,:=", state)
    print("%x" % z3.simplify(state.registers["eflags"]).as_long())
    #print(state.popAndEval())

def test_run():
    r2p = r2pipe.open("tests/simplish", flags=["-2"])
    r2p.cmd("s sym.check; aei; aeim; aer rdi=12605")

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    #esilsolver.initVM()

    state = esilsolver.init_state()
    state.set_symbolic_register("rdi")
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


def test_multi_addr():
    r2p = r2pipe.open("-", flags=["-2"])
    r2p.cmd("wa mov [rax], rbx")

    esilsolver = ESILSolver(r2p, debug=True, trace=False)
    #esilsolver.initVM()

    state = esilsolver.init_state()
    state.set_symbolic_register("rax")
    rax = state.registers["rax"]
    state.solver.add(rax > 7)
    state.solver.add(rax < 16)

    esilsolver.run(target=0x00000003)

    sat = state.solver.check()
    #print(state.solver)
    print(sat)
    m = state.solver.model()
    print(m.eval(rax))
    #print(state.solver.statistics())

def test_newreg():
    esilsolver = ESILSolver()
    state = esilsolver.states[0]
    esilsolver.parse_expression("1,rax,+=[8],rax,[8],1,+", state)
    print(state.stack)

def test_cond():
    esilsolver = ESILSolver(debug=True)
    state = esilsolver.init_state()
    state.proc.parse_expression("0,?{,1,rax,=,}", state)
    print(state.stack)
    print(state.registers["rax"])

def test_multi():
    r2p = r2pipe.open("tests/multibranch", flags=["-2"])
    r2p.cmd("aa; s sym.check; aei; aeim; aer rdi=22021")

    esilsolver = ESILSolver(r2p, optimize=False, debug=False, trace=False)
    #esilsolver.initVM()

    state = esilsolver.init_state()
    state.set_symbolic_register("rdi")
    #state.registers["rdi"] = solver.BitVecVal(0xdead, 64)
    rdi = state.registers["rdi"]

    esilsolver.run(target=0x0000066f)
    #print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)
    state = esilsolver.run(target=0x0000069f)
    #print(state.registers["zf"])
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
    r2p.cmd("s sym.check; aei; aeim; aer rdi=22021")

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    #esilsolver.initVM()

    state = esilsolver.init_state()
    state.set_symbolic_register("rdi")
    rdi = state.registers["rdi"]
    state.solver.add(rdi >= 0)

    def success(state):
        sat = state.solver.check()
        m = state.solver.model()
        print("ARG1: %d" % m.eval(rdi).as_long())
        return True

    esilsolver.register_hook(0x6a1, success)
    esilsolver.run(target=0x000006a1, avoid=[0x000006a8])

def test_multi32():
    r2p = r2pipe.open("tests/multi32", flags=["-2"])
    r2p.cmd("s sym.check; aei; aeim; wv 162517261 @ 0x00178004")

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    #esilsolver.initVM()
    state = esilsolver.init_state()
    state.memory.write_bv(0x00178004, solver.BitVec("arg1", 32), 4)

    state = esilsolver.run(target=0x0000052d)
    eax = state.registers["eax"]

    state = esilsolver.run(target=0x00000558)
    state.solver.add(state.registers["zf"] == 1)

    state = esilsolver.run(target=0x00000588)
    print(state.registers["zf"])
    state.solver.add(state.registers["zf"] == 1)

    print("solving")
    sat = state.solver.check()
    print(sat)

    m = state.solver.model()
    print(m.eval(eax))

def test_arm():
    local = True

    funcaddr = 0
    varaddr = 0x100000
    stackaddr = 0x200000
    if local:
        r2p = r2pipe.open("ipa://tests/crackme-level0-symbols.ipa", flags=["-2"])
        # w ewmfpkzbjowr hvb @ 0x100000
        r2p.cmd("s sym._validate; aei; aeim; aer x0 = 0x100000;")
        funcaddr = int(r2p.cmd("s"), 16)
    else:
        r2p = r2pipe.open("frida://133ebc680e67c885e7f04621481d8a0229bef371//com.nowsecure.crackme", flags=["-2"])
        r2p.cmd("\dc; `\il~:0[0]`; `\is~validate$:0[0]`;") # r2 pro mode
        funcaddr = int(r2p.cmd("s"), 16)
        varaddr = int(r2p.cmd("\dma 0x1000"), 16)
        stackaddr = int(r2p.cmd("\dma 0x2000"), 16) + 0x1000
        r2p.cmd("aei; aeip; aer x0=%d; aer sp=%d; aer fp=%d;" % (varaddr, stackaddr, stackaddr))

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    state = esilsolver.init_state()

    b = [z3.BitVec("b%d" % x, 8) for x in range(16)]
    for x in range(16):
        state.constrain(z3.Or(z3.And(b[x] >= 0x61, b[x] <= 0x7a), b[x] == 0x20))

    code = z3.Concat(*b)
    state.memory.write_bv(varaddr, code, 16)

    def success(state):
        cs = state.evaluate_buffer(code)
        #print(cs)
        print("CODE: '%s'" % cs.decode())

    esilsolver.register_hook(funcaddr+0x210, success)
    esilsolver.run(target=funcaddr+0x210, avoid=[funcaddr+0x218, funcaddr+0x3c])

if __name__ == "__main__":
    #test_cond()
    #test_sym()
    #test_mem()
    #test_flg()
    #test_run()
    #test_newreg()
    #test_multi()
    #test_multi_hook()
    #test_multi32()
    test_arm()
    #test_multi_addr()