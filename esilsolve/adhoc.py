# a place for awful adhoc fixes to instructions
# that will be tough to fix in r2 
import logging 
logger = logging.getLogger("esilsolve")

# fuckin capstone
need_flags = ["adds", "subs", "ands"]
def fix_instruction(info, instr):
    #print(info, instr)
    mnem = instr.get("disasm", "").split(" ")[0]
    arch = info.get("info",{}).get("arch")

    if arch == "arm" and mnem in need_flags:
        esil = instr["esil"]
        if "w" in instr["disasm"]:
            esil += ",$z,zf,:=,31,$s,nf,:=,32,$b,!,cf,:=,31,$o,vf,:="
        else:
            esil += ",$z,zf,:=,63,$s,nf,:=,64,$b,!,cf,:=,63,$o,vf,:="
        
        instr["esil"] = esil
