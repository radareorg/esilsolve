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

op_dict = {}
bits = [1, 8, 16, 32, 64] #, 128] 128 is not supported

for bit in bits:
    for sign in ("", "U", "S"):
        for bit2 in bits:
            op_key = "Iop_%d%sto%d" % (bit, sign, bit2)
            if bit == bit2:
                continue

            elif bit2 < bit:
                if sign != "S":
                    op_dict[op_key] = [0, hex((1<<bit2)-1), "&"]
                else:
                    op_dict[op_key] = [str(bit), 0, hex((1<<bit)-1), "&", "~", hex((1<<bit2)-1), "&"]
            else:
                if sign != "S":
                    if bit == 64:
                        op_dict[op_key] = [0]
                    else:
                        op_dict[op_key] = [0, hex((1<<bit)-1), "&"]
                else:
                    op_dict[op_key] = [str(bit), 0, hex((1<<bit)-1), "&", "~", hex((1<<bit2)-1), "&"]

            op_key = "Iop_%dHIto%d" % (bit, bit2)
            op_dict[op_key] = [str(bit-bit2), 0, ">>", hex((1<<bit2)-1), "&"]

            op_key = "Iop_%dHLto%d" % (bit, bit2)
            op_dict[op_key] = [str(bit2-bit), 1, "<<", 0, "+"]

        op_key = "Iop_Add%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "+"]

        op_key = "Iop_Sub%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "-"]

        op_key = "Iop_Mul%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "*"]

        op_key = "Iop_Or%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "|"]

        op_key = "Iop_Xor%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "^"]

        op_key = "Iop_And%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "&"]

        op_key = "Iop_Shl%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "<<"]

        op_key = "Iop_Shr%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, ">>"]

        op_key = "Iop_Sar%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, ">>>>"]

        op_key = "Iop_CmpEQ%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "-", "!"]

        op_key = "Iop_CmpNE%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "-", "!", "!"]

        op_key = "Iop_CmpLT%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "<"]

        op_key = "Iop_CmpLTE%s%d" % (sign, bit)
        op_dict[op_key] = [0, 1, "<="]

        op_key = "Iop_Not%s%d" % (sign, bit)
        op_dict[op_key] = [0, "!"]

        op_key = "Iop_Mull%s%d" % (sign, bit)
        sbit = str(bit)
        if sign != "S":
            op_dict[op_key] = [0, 1, "*"]
        else:
            op_dict[op_key] = [sbit, 0, "~", sbit, 1, "~", "*"]

        op_key = "Iop_Div%s%d" % (sign, bit)
        if sign != "S":
            op_dict[op_key] = [0, 1, "/"]
        else:
            op_dict[op_key] = [sbit, 0, "~", sbit, 1, "~", "~/"]


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

        self.do_lookahead = True

    def convert_str(self, instruction=None, code=None):
        r2p = r2pipe.open("-", ["-a", self.arch, "-b", str(self.bits), "-2"])
        self.r2p = r2p

        if instruction == None:
            r2p.cmd("wx %s" % hexlify(code).decode())
        else:
            r2p.cmd("wa %s" % instruction)

        instr = r2p.cmdj("pdj 1")[0]

        return self.convert(instr, code=code)

    def convert_c(self, instruction=None, code=None):
        esilex = self.convert_str(instruction, code)
        return self.replace_regs(instruction, esilex)

    def convert(self, instr, code=None):
        if code == None:
            print(instr["bytes"])
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
        self.temp_to_exprs = {}
        self.skip_next = False

        for ind, statement in enumerate(self.irsb.statements):
            if self.skip_next:
                self.skip_next = False
                continue

            #print(type(statement))
            #print(dir(statement))
            #print(dir(statement.data))
            stmt_type = type(statement)
            next_stmt = None
            if len(self.irsb.statements) > ind+1:
                next_stmt = self.irsb.statements[ind+1]

            if stmt_type == WrTmp:
                #print(dir(statement.data))
                
                # look ahead to see if the stmt is a reg get
                # and the next stmt is a conv
                if self.do_lookahead:
                    if type(statement.data) in (Get, GetI):
                        src, size = self.offset_to_reg(statement.data, True)
                        conv_op = "%dto" % (size*8)

                        if type(next_stmt) == Unop and type(next_stmt.data) in self.ops and conv_op in next_stmt.data.op:
                            to_size = next_stmt.data.op[4+len(conv_op):]

                            if to_size.isdigit():
                                new_size = int(to_size)//8
                                new_offset = statement.data.offset

                                if (new_offset, new_size) in self.arch_class.register_size_names:
                                    new_exprs = [self.arch_class.register_size_names[(new_offset, new_size)]]
                                    self.temp_to_exprs[next_stmt.tmp] = new_exprs
                                    self.skip_next = True
                                    continue

                    elif type(next_stmt) in (Put, PutI):
                        dst, size = self.offset_to_reg(next_stmt)
                        conv_op = "to%d" % (size*8)

                        if type(statement.data) in self.ops and conv_op in statement.data.op:
                            to_size = statement.data.op[4:statement.data.op.index(conv_op)][:2]
                            if to_size[0] == "8":
                                to_size = "8"

                            if to_size.isdigit():
                                new_size = int(to_size)//8
                                new_offset = next_stmt.offset

                                if (new_offset, new_size) in self.arch_class.register_size_names:
                                    new_dst = self.arch_class.register_size_names[(new_offset, new_size)]
                                    self.exprs += self.temp_to_exprs[statement.data.args[0].tmp] + [new_dst, "="]
                                    self.skip_next = True
                                    continue

                new_exprs = self.data_to_esil(statement.data)
                self.temp_to_exprs[statement.tmp] = new_exprs

            elif stmt_type in (Put, PutI):
                dst, size = self.offset_to_reg(statement)
                if "cc_" not in dst: # skip flags for now
                    self.exprs += self.data_to_esil(statement.data, dst=dst)

            elif stmt_type in (Store, StoreG):
                size = int(statement.data.result_size(self.irsb.tyenv)/8)
                self.exprs += self.data_to_esil(statement.data)
                self.exprs += self.temp_to_exprs[statement.addr.tmp]
                self.exprs += ["=[%d]" % size]

            elif stmt_type == Exit:
                pass

        #print(self.exprs) 
        esilex = ",".join(self.exprs)

        esilchecker = ESILCheck(self.arch, bits=self.bits)
        #esilchecker.check(code=code, check_flags=False)
        esilchecker.check(code=code, esil=esilex, check_flags=False)

        #print(esilex)
        return esilex

    def replace_regs(self, instr, esilex):
        regs = dict([(reg["name"], reg) for reg in self.r2p.cmdj("aerpj")["reg_info"]])
        new_esilex = []
        arg_strs = []
        args = []
        if " " in instr:
            args = " ".join(instr.split(" ")[1:]).split(", ")

        def arg_index(word):
            for ind, arg in enumerate(args):
                if word in arg:
                    return ind

                elif word.isdigit() and "0x"+word in arg:
                    return ind
                
                elif word[:2] == "0x" and str(int(word, 16)) in arg:
                    return ind

            return -1

        for word in esilex.split(","):
            if word in regs and arg_index(word) != -1:
                new_esilex.append("%1$s")
                arg_strs.append("REG(%d)" % arg_index(word))
            elif word.isdigit() or word[:2] == "0x" and arg_index(word) != -1:
                new_esilex.append("%d")
                arg_strs.append("IMM(%d)" % arg_index(word))
            else:
                new_esilex.append(word)

        replaced = ",".join(new_esilex)
        c_code = 'esilprintf("%s", %s)' % (replaced, ", ".join(arg_strs))
        return c_code

    def offset_to_reg(self, stmt, is_data=False):
        offset = stmt.offset
        if is_data:
            size = int(stmt.result_size(self.irsb.tyenv)/8)
        else:
            size = int(stmt.data.result_size(self.irsb.tyenv)/8)

        return self.arch_class.register_size_names[(offset, size)], size

    def data_to_esil(self, data, dst=None, flag=False):
        exprs = []
        dtype = type(data)

        if dtype == Const:
            exprs.append("0x%x" % data.con.value)

        elif dtype == RdTmp:
            exprs += self.temp_to_exprs[data.tmp] #["%d" % temp, "RPICK"]

        elif dtype in (Get, GetI):
            src, size = self.offset_to_reg(data, True)
            exprs += [src]

        elif dtype in self.ops:
            args = data.args[::-1]
            exprs += self.do_op(data.op, args)

        elif dtype == Load:
            size = int(data.result_size(self.irsb.tyenv)/8)
            exprs += self.temp_to_exprs[data.addr.tmp]
            exprs += ["[%d]" % size]
            
        if dst != None:
            eq = "="
            if flag: eq = ":="
            exprs += [dst, eq]

        return exprs

    def do_op(self, op, args):
        final_exprs = []
        op_key = op

        if op_key in op_dict:
            exprs = op_dict[op_key]
            for expr in exprs:
                if type(expr) == int:
                    val = self.data_to_esil(args[expr])
                    final_exprs += val
                else:
                    final_exprs += [expr]

            return final_exprs

        else:
            raise VexException("op %s not found" % op_key)
            #return []

class VexException(Exception):
    pass

if __name__ == "__main__":

    vexconv = Vex2Esil("arm", bits=64)
    #print(vexconv.convert("cdq"))
    #print(vexconv.convert("mov [rax], rbx"))
    print(vexconv.convert_str(code=unhexlify("88cf1fb8")))
    #vexconv.convert(code=b"\x20\xc0\x1f\x38")