from pyvex import lift
from pyvex.stmt import Put, PutI, Store, StoreG, WrTmp, Exit
from pyvex.expr import Get, GetI, Load, RdTmp
from pyvex.expr import Const, Unop, Binop, Triop, Qop

import archinfo
import capstone
import r2pipe
from binascii import hexlify, unhexlify

from esilcheck import ESILCheck

arch_dict = {
    64: {"arm": "aarch64", "x86": "amd64"}
}

archinfo_dict = {
    "x86": archinfo.ArchX86,
    "arm": archinfo.ArchARM,
    "aarch64": archinfo.ArchAArch64,
    "amd64": archinfo.ArchAMD64,
    "mips": archinfo.ArchMIPS32,
    "mips64": archinfo.ArchMIPS64
}

op_dict = {
    # ints reference arguments
    "Iop_Add": [0, 1, "+"],
    "Iop_Sub": [0, 1, "-"],
    "Iop_Mul": [0, 1, "*"],
    "Iop_MullU": [0, 1, "*"],
    "Iop_MullS": [0, "$sz", "~", 1, "$sz", "~", "*"],
    "Iop_Div": [0, 1, "/"],
    "Iop_DivU": [0, 1, "/"],
    "Iop_DivS": [0, "$sz", "~", 1, "$sz", "~", "/"],
    "Iop_Or": [0, 1, "|"],
    "Iop_Xor": [0, 1, "^"],
    "Iop_And": [0, 1, "&"],
    "Iop_Shl": [0, 1, "<<"],
    "Iop_Shr": [0, 1, ">>"],
    "Iop_Sar": [0, 1, ">>>>"],
    "Iop_CmpEQ": [0, 1, "-", "!"],
    "Iop_CmpNE": [0, 1, "-"],
    "Iop_CmpLT": [0, 1, "<"],
    "Iop_CmpLTE": [0, 1, "<="],
    "Iop_Not": [0, "!"],
}

# i was drunk when i wrote all of this
# so take that into consideration pls
bits = [1, 8, 16, 32, 64] #, 128] 128 is not supported

for bit in bits:
    for sign in ("", "U", "S"):
        if sign != "S":
            op_key = "Iop_%d%sto" % (bit, sign)
            op_dict[op_key] = [0, "1", "$sz", "1", "<<", "-", "&"]
        else:
            op_key = "Iop_%d%sto" % (bit, sign)
            op_dict[op_key] = [0, "%d" % bit, "~", "1", "$sz", "1", "<<", "-", "&"]

        op_key = "Iop_DivMod%s%dto" % (sign, bit)
        op_dict[op_key] = [0, 1, "/", "%d" % int(bit/2),  0, 1, "%", "<<", "+"]

    op_key = "Iop_%dHIto" % bit
    op_dict[op_key] = ["$sz", "%d" % bit, "-", 0, ">>"]

    op_key = "Iop_%dHLto" % bit
    op_dict[op_key] = ["$sz", "%d" % bit, "-", 0, ">>", 1, "+"]


# Automatically translate vex into truly terrible esil expressions
# do not look directly at the results
class Vex2Esil:

    def __init__(self, arch, bits=64):
        self.arch = arch
        self.bits = bits

        self.aarch = self.arch
        if bits in arch_dict and arch in arch_dict[bits]:
            self.aarch = arch_dict[bits][arch]

        self.arch_class = archinfo_dict[self.aarch]()
        self.vex_addr = 0x400400
        self.ops = [Unop, Binop, Triop, Qop]

    def convert(self, instruction=None, code=None):
        r2p = r2pipe.open("-", ["-a", self.arch, "-b", str(self.bits), "-2"])

        if instruction == None:
            r2p.cmd("wx %s" % hexlify(code).decode())
        else:
            r2p.cmd("wa %s" % instruction)

        instr = r2p.cmdj("pdj 1")[0]
        code = unhexlify(instr["bytes"])
        print(instr["esil"])
        if all([x == 0 for x in code]):
            print("[!] failed to assemble instruction")
            return 

        self.irsb = lift(code, self.vex_addr, self.arch_class)
        self.irsb.pp()

        self.exprs = []
        self.stacklen = 0
        self.temp_to_stack = {}

        for statement in self.irsb.statements:
            #print(statement)
            #print(dir(statement))
            #print(dir(statement.data))
            stmt_type = type(statement)
            if stmt_type == WrTmp:
                #print(dir(statement.data))
                self.temp_to_stack[statement.tmp] = self.stacklen
                self.stacklen += 1
                self.exprs += self.data_to_esil(statement.data)

            elif stmt_type in (Put, PutI):
                dst = self.offset_to_reg(statement)
                if "cc_" not in dst: # skip flags for now
                    self.exprs += self.data_to_esil(statement.data, dst=dst)

            elif stmt_type in (Store, StoreG):
                size = int(statement.data.result_size(self.irsb.tyenv)/8)
                temp = self.temp_to_stack[statement.addr.tmp]
                self.exprs += self.data_to_esil(statement.data)
                self.exprs += ["%d" % temp, "RPICK", "=[%d]" % size]

            elif stmt_type == Exit:
                pass

        #print(self.exprs)
        esilex = ",".join(self.exprs)

        esilchecker = ESILCheck(self.arch, bits=self.bits)
        esilchecker.check(instr["disasm"], esil=esilex)

        return esilex

    def offset_to_reg(self, stmt, data=False):
        offset = stmt.offset
        if data:
            size = int(stmt.result_size(self.irsb.tyenv)/8)
        else:
            size = int(stmt.data.result_size(self.irsb.tyenv)/8)

        return self.arch_class.register_size_names[(offset, size)]

    def data_to_esil(self, data, dst=None, flag=False):
        exprs = []
        dtype = type(data)

        if dtype == Const:
            exprs.append("%d" % data.con.value)

        elif dtype == RdTmp:
            temp = self.temp_to_stack[data.tmp]
            exprs += ["%d" % temp, "RPICK"]

        elif dtype in (Get, GetI):
            src = self.offset_to_reg(data, True)
            exprs += [src]

        elif dtype in self.ops:
            args = data.args[::-1]
            self.stacklen += len(args)

            # push args in do_op 
            # for arg in args:
            #     exprs += self.data_to_esil(arg)

            exprs += self.do_op(data.op, args)
            self.stacklen -= len(args)

        elif dtype == Load:
            size = int(data.result_size(self.irsb.tyenv)/8)
            temp = self.temp_to_stack[data.addr.tmp]
            exprs += ["%d" % temp, "RPICK", "[%d]" % size]
            
        if dst != None:
            eq = "="
            if flag: eq = ":="
            exprs += [dst, eq]

        return exprs

    def do_op(self, op, args):
        final_exprs = []
        to_size, op_key, sign = self.get_op_size(op)
        #print(to_size, op_key, sign)
        if op_key in op_dict:
            exprs = op_dict[op_key]
            for expr in exprs:
                if type(expr) == int:
                    val = self.data_to_esil(args[expr])
                    if sign != "S":
                        final_exprs += val
                    else:
                        final_exprs += val # + [""] # handle this later im tired
                elif expr == "$sz":
                    final_exprs += ["%d" % to_size]
                else:
                    final_exprs += [expr]

            return final_exprs

        else:
            print("op %s not found" % op_key)
            raise VexException
            #return []

    def get_op_size(self, op):
        s = 0
        sign = ""
        for i in range(1, 4):
            if op[-i:].isdigit():
                s += 1
            elif op[-i:] == "S":
                sign = "S"
                s += 1
            elif op[-i:] == "U":
                sign = "U"
                s += 1

        c = None
        if op[-1] == sign:
            c = -1

        return (int(op[-s:c]), op[:-s], c)

class VexException(Exception):
    pass

if __name__ == "__main__":

    vexconv = Vex2Esil("x86", bits=64)
    #vexconv.convert("xor rax, rbx")
    #vexconv.convert("mov rax, [rbx]")
    vexconv.convert("imul ebx")