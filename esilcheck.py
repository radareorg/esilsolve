from esilsolve import ESILSolver
import angr
import claripy
import solver
import r2pipe
from binascii import hexlify, unhexlify
import re
import logging

logging.getLogger('angr').setLevel('ERROR')
reg_pattern = re.compile('^reg_([a-z0-9]+)_\\d+_\\d+$')
mem_pattern = re.compile('^mem_([a-f0-9]+)_\\d+_(\\d+)$')

class ESILCheck:
    def __init__(self, arch, bits=64):
        self.arch = arch
        self.bits = bits
        self.converter = claripy.backends.z3

    def check(self, instruction=None, code=None):
        r2p = r2pipe.open("-", ["-a", self.arch, "-b", str(self.bits), "-2"])

        if instruction == None:
            r2p.cmd("wx %s" % hexlify(code).decode())
        else:
            r2p.cmd("wa %s" % instruction)

        instr = r2p.cmdj("pdj 1")[0]
        code = unhexlify(instr["bytes"])
        if all([x == 0 for x in code]):
            print("[!] failed to assemble instruction")
            return 

        print("[*] instruction: %s : %s\n" % (instr["opcode"], instr["esil"]))

        esilsolver = ESILSolver(r2p, sym=True)
        esstate = esilsolver.init_state()
        esstate.registers["PC"] = solver.BitVecVal(0, 32)

        esclone = esstate.clone()

        proj = angr.load_shellcode(code, arch=self.arch)
        state = proj.factory.blank_state()
        block = proj.factory.block(proj.entry)

        successor = state.step()[0]
        essuccessor = esclone.step()[0]
        basesolver = self.converter.solver()

        insn = block.capstone.insns[0].insn
        regs_read, regs_write = insn.regs_access()

        print("[-] read: ")
        for reg in regs_read:
            regn = insn.reg_name(reg)

            try:
                regv = getattr(successor.regs, regn)
                esregv = essuccessor.registers[regn]
                print("[+]\tangr %s: %s" % (regn, trunc(regv)),)
                print("[+]\t ES  %s: %s" % (regn, trunc(esregv)),)
            except Exception as e:
                print("[!] error with read reg %s: %s" % (regn, str(e)))
        
        print("\n[-] write: ")
        for reg in regs_write:
            basesolver.push()
            equated = {}

            regn = insn.reg_name(reg)
            try:
                regv = getattr(successor.regs, regn)

                esregv = essuccessor.registers[regn]
                regv = getattr(successor.regs, regn)
                convregv = self.converter.convert(regv)
                basesolver.add(esregv != convregv)

                print("[+]\tangr %s: %s" % (regn, trunc(regv)),)
                print("[+]\t ES  %s: %s" % (regn, trunc(esregv)),)

                self.equate_regs(basesolver, convregv, esstate, essuccessor, equated)
            except Exception as e:
                print("[!] error with write reg %s: %s" % (regn, str(e)))

            satisfiable = basesolver.check()
            if satisfiable == solver.sat:
                model = basesolver.model()
                print("[!]\tunequal model: %s" % str(model).replace("\n", ""))
                print("[*]\t\tangr %s: %x" % (regn, model.eval(convregv).as_long()))
                print("[*]\t\t ES  %s: %x\n" % (regn, model.eval(esregv).as_long()))

            else:
                print("[*]\timplementations are equivalent!\n")
            
            basesolver.pop()

    def equate_regs(self, basesolver, angrstmt, esstate, essuccessor, equated, depth=0):
        esreg = self.stmt_to_reg(angrstmt)
        if esreg != None:
            if esreg not in equated:
                basesolver.add(angrstmt == esstate.registers[esreg])
                equated[esreg] = True
        else:
            esmem = self.stmt_to_mem(angrstmt)
            if esmem != None:
                esmemname = "mem_%016x" % esmem["addr"]
                if esmemname not in equated:
                    # jesus this script has some bad hacks in it
                    esaddr = list(essuccessor.memory._memory.keys())[0]
                    esdata = essuccessor.memory.read_bv(esaddr, int(esmem["size"]/8))
                    basesolver.add(angrstmt == esdata)
                    equated[esmemname] = True
            else:
                for child in angrstmt.children():
                    #print("[*]%schild: %s" % ("\t"*(depth+2),trunc(child)))
                    self.equate_regs(basesolver, child, esstate, essuccessor, equated, depth+1)

    # this is terrible but its what I have until I find out 
    # how to do the conversion properly, if it is even possible
    def stmt_to_reg(self, stmt):
        stmt_str = str(stmt)
        matches = re.search(reg_pattern, stmt_str)

        if matches == None:
            return
        else:
            return matches.group(1)

    def stmt_to_mem(self, stmt):
        stmt_str = str(stmt)
        matches = re.search(mem_pattern, stmt_str)

        if matches == None:
            return
        else:
            return {
                "addr": int(matches.group(1), 16),
                "size": int(matches.group(2))
            }

def trunc(s, maxlen=64):
    s = str(s).replace("\n", " ")
    if len(s) > maxlen:
        return s[:maxlen] + "..."
    else:
        return s

if __name__ == "__main__":
    esilcheck = ESILCheck("x86", bits=32)
    esilcheck.check("add eax, ebx")
    esilcheck.check("sub eax, ebx")

    esilcheck.check("imul eax") # edx not equivalent

    quit()

    esilcheck = ESILCheck("arm", bits=32)
    esilcheck.check("add r0, r0, r1")
    esilcheck.check("sub r0, r0, r1")

    esilcheck = ESILCheck("amd64", bits=64)
    esilcheck.check("add rax, rbx")
    esilcheck.check("sub rax, rbx")

    esilcheck = ESILCheck("x86", bits=32)
    esilcheck.check("add eax, [ebx]")
    esilcheck.check("sub eax, [ebx]")