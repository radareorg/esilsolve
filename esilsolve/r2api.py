import r2pipe
import binascii

class R2API:
    """ API for interacting with r2 through r2pipe """

    def __init__(self, r2p=None, filename="-", flags=["-2"]):
        self.r2p = r2p
        if r2p == None:
            self.r2p = r2pipe.open(filename, flags=flags)

        self.instruction_cache = {}
        self.cache_num = 64
        self.ccs = {}

        self.register_info = None
        self.get_register_info()
        self.info = None

    def get_info(self):
        if self.info == None:
            self.info = self.r2p.cmdj("iaj")

        return self.info

    def get_register_info(self):
        if self.register_info == None:
            self.register_info = self.r2p.cmdj("aerpj")
            self.all_regs = [r["name"] for r in self.register_info["reg_info"]] 

        return self.register_info

    def get_reg_value(self, reg):
        return int(self.r2p.cmd("aer %s" % reg), 16)

    def set_reg_value(self, reg, value):
        self.r2p.cmd("aer %s=%d" % (reg, value))

    def get_gpr_values(self):
        return self.r2p.cmdj("aerj")

    def seek(self, addr):
        self.r2p.cmd("s %s" % str(addr))

    def step(self, sz):
        self.r2p.cmd("s+ %d" % sz)

    def disass(self, addr=None, instrs=1):
        if addr in self.instruction_cache and instrs == 1:
            return self.instruction_cache[addr]

        cmd = "pdj %d" % max(instrs, self.cache_num)
        if addr != None:
            cmd += " @ %d" % addr

        result = self.r2p.cmdj(cmd)
        for instr in result:
            self.instruction_cache[instr["offset"]] = instr

        if instrs == 1:
            return result[0]

        return result[:instrs]

    def disass_function(self, addr=None):
        cmd = "pdfj"
        if addr != None:
            cmd += " @ %d" % addr

        result = self.r2p.cmdj(cmd)
        for instr in result["ops"]:
            self.instruction_cache[instr["offset"]] = instr

        return result["ops"]

    def read(self, addr, length):
        return self.r2p.cmdj("xj %d @ %d" % (length, addr))

    def write(self, addr, value, length=None, fill="0"):
        val = value
        if type(value) == int:
            if length == None:
                length = int(self.info["info"]["bits"]/8)

            return self.r2p.cmd("wv%d %d @ %d" % (length, value, addr))

        elif type(value) == bytes:
            val = binascii.hexlify(value).decode()

        if length != None:
            val = val.rjust(length, str(fill))

        cmd = "wx %s @ %d" % (val, addr)
        #print(cmd)
        return self.r2p.cmd(cmd)

    # theres no arj all function to get all the regs as json so i made this
    # i should just make a pull request for r2
    def get_all_registers(self):
        reg_dict = {}
        reg_str = ",".join(self.all_regs)
        val_str = self.r2p.cmd("aer %s" % reg_str)
        # this got a little too long
        all_vals = list(map(lambda x: int(x, 16), val_str.split("\n")[:-1]))

        for i in range(len(all_vals)):
            reg_dict[self.all_regs[i]] = all_vals[i]

        return reg_dict

    def init_vm(self):
        self.r2p.cmd("aei; aeim")

    def emu(self, instr):
        self.r2p.cmd("ae %s" % instr["esil"])

    def emustep(self):
        self.r2p.cmd("aes")

    def function_info(self, func):
        return self.r2p.cmdj("af %s; afij %s" % (str(func), str(func)))[0]

    # get calling convention for sims
    def calling_convention(self, func):
        if func in self.ccs:
            return self.ccs[func]
        else:
            self.ccs[func] = self.r2p.cmdj("afcrj @ %s" % str(func))
            return self.ccs[func]

    def get_address(self, func):
        return self.r2p.cmdj("pdj 1 @ %s" % str(func))[0]["offset"]

    def analyze(self, level=3): # level 7 solves ctfs automatically
        self.r2p.cmd("a"*level)