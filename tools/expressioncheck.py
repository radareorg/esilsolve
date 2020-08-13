import r2pipe
import sys 
#from vex2esil import Vex2Esil
from esilcheck import ESILCheck
from binascii import unhexlify

# identify structurally different (arm) instrs, jankily
def get_op_key(instr):
    parts = instr["opcode"].split(" ")
    op = parts[0]
    args = []
    if len(parts) > 1:
        args_str = "".join(parts[1:])
        
        for arg in args_str.split(","):
            if arg[0] == "-":
                args.append(-1)
            elif arg[:2] == "0x" or arg.isdigit():
                args.append(0)
            elif "[" in arg:
                args.append(1)
            elif "lsl" in arg:
                args.append(5)
            elif "sxt" in arg:
                args.append(6)
            elif "uxt" in arg:
                args.append(7)
            elif "x" in arg:
                args.append(2)
            elif "w" in arg:
                args.append(3)
            else:
                # ??? 
                args.append(4)

    return "_".join([str(x) for x in ([op] + args)])

def expression_check(prog): 
    instr_dict = {}

    start_count = len(instr_dict.keys())
    r2p = r2pipe.open(prog)

    info = r2p.cmdj("ij")["bin"]
    esilcheck = ESILCheck(info["arch"], bits=info["bits"])

    r2p.cmd("aa")
    funcs = r2p.cmdj("aflj")

    for func in funcs:
        try:
            instrs = r2p.cmdj("pdfj @ %d" % func["offset"])["ops"]

            for instr in instrs:
                if instr["esil"] not in ("", "TODO") and instr["type"] not in ("call","cjmp","jmp"):
                    op_key = get_op_key(instr)
                    #print(op_key)

                    if op_key not in instr_dict:
                        print("-"*120 + "\n")
                        print("%016x:\t%16s\t%s " % (instr["offset"], instr["bytes"], instr["opcode"]))
                        try:
                        #if True:
                            #print(vexconv.convert(instr))
                            esilcheck.check(code=unhexlify(instr["bytes"]))
                        except Exception as e:
                            print("error: %s" % str(e))
                        print("\n" + "-"*120)
                        instr_dict[op_key] = instr
                        
                    #else:
                    #    print("%016x:\t%16s\t%s (dup)" % (instr["offset"], instr["bytes"], instr["opcode"]))

            #if len(instr_dict.keys()) > start_count:
            #    break
        except:
            continue

if __name__ == "__main__":
    expression_check(sys.argv[1])