import r2pipe

class R2API:

    def __init__(self, r2p=None, filename="-", flags=[]):
        self.r2p = r2p
        if r2p == None:
            self.r2p = r2pipe.open(filename, flags=flags)

        self.register_info = self.r2p.cmdj("aerpj")
        self.all_regs = [r["name"] for r in self.register_info["reg_info"]]

    def getInfo(self):
        return self.r2p.cmdj("iaj")

    def getRegisterInfo(self):
        self.register_info = self.r2p.cmdj("aerpj")
        self.all_regs = [r["name"] for r in self.register_info["reg_info"]]
        return self.r2p.cmdj("aerpj")

    def getRegValue(self, reg):
        return int(self.r2p.cmd("ar %s" % reg), 16)

    def getGPRValues(self):
        return self.r2p.cmdj("aerj")

    def seek(self, addr):
        self.r2p.cmd("s %d" % addr)

    def disass(self, instrs=1):
        return self.r2p.cmdj("pdj %d" % instrs)

    # theres no arj all function to get all the regs as json so i made this
    # i should just make a pull request for r2
    def getAllRegisters(self):
        reg_dict = {}
        reg_str = ",".join(self.all_regs)
        val_str = self.r2p.cmd("ar %s" % reg_str)
        # this got a little too long
        all_vals = list(map(lambda x: int(x, 16), val_str.split("\n")[:-1]))

        for i in range(len(all_vals)):
            reg_dict[self.all_regs[i]] = all_vals[i]

        return reg_dict

