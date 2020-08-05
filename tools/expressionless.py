import r2pipe
import sys 
from vex2esil import Vex2Esil
from binascii import unhexlify

def get_expressionless(prog): 
    instr_dict = {
    }
    nvmd = {
        "mrs": 0, # TODO this.
        "msr": 0,
        #"ldaxr": 0,
        #"ldxr": 0,
        "stlxr": 0, # no capstone 
        "brk": 0, # break, idk if we want to BREAK?
        "dmb": 0, # fence, ignore
        "dsb": 0, # fence, ignore
        "isb": 0, # fence, ignore
        "umulh": 0, # 128 bit expression, we will address this
        "smulh": 0, # ditto
        "hint": 0, # probably not relevant for us
        "movi": 0, # fp instr ?
        "fdiv": 0, # ditto
        "fmov": 0, # ...
        "fmul": 0, # ... 
        "fabs": 0, # ...
        "fadd": 0, # yep
        "fsub": 0, # really need to make the fp mode
        "dup": 0, # 128 bit instr
        "dc": 0, # nop? 
        "ic": 0, # idk? 
        "ld1": 0, # 128 bit
        "cmeq": 0, # 128 bit
        "addp": 0, # 128 bit
        "prfm": 0, # memory hint thing, ignore
        #"rbit": 1, # the crazy one, save for a good time
    }

    start_count = len(instr_dict.keys())
    r2p = r2pipe.open(prog)
    info = r2p.cmdj("ij")["bin"]
    vexconv = Vex2Esil(info["arch"], bits=info["bits"])

    r2p.cmd("aa")
    funcs = r2p.cmdj("aflj")

    for func in funcs:
        instrs = r2p.cmdj("pdfj @ %d" % func["offset"])["ops"]

        for instr in instrs:
            if instr["esil"] in ("", "TODO") and instr["type"] not in ("nop", "ill"):
                op = instr["opcode"].split(" ")[0]
                if op not in instr_dict:
                    print("-"*120 + "\n")
                    print("%016x:\t%16s\t%s " % (instr["offset"], instr["bytes"], instr["opcode"]))
                    #try:
                    if True:
                        #print(vexconv.convert(instr))
                        print(vexconv.convert_c(instr["disasm"], code=unhexlify(instr["bytes"])))
                    #except Exception as e:
                    #    print("error: %s" % str(e))
                    print("\n" + "-"*120)
                    instr_dict[op] = instr
                    
                #else:
                #    print("%016x:\t%16s\t%s (dup)" % (instr["offset"], instr["bytes"], instr["opcode"]))

        if len(instr_dict.keys()) > start_count:
            break

if __name__ == "__main__":
    get_expressionless(sys.argv[1])