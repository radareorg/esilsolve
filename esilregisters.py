
from esilclasses import *
import solver

class ESILRegisters(dict):
    def __init__(self, reg_array, aliases={}):
        self.reg_info = reg_array
        self._registers = {}
        self.aliases = aliases

        self.parent_dict = {}
        self.super = None

        for reg in reg_array:
            self.processRegister(reg)

    def processRegister(self, reg):
        parentRegister = self.getParentRegister(reg)

        if parentRegister == None:
            # register is not a subregister, give it a BV
            reg["parent"] = None

            if "value" in reg:
                reg["bv"] = solver.BitVecVal(reg.pop("value"), reg["size"])

        else:
            reg["parent"] = parentRegister["name"]
            reg["low"] = reg["offset"] - parentRegister["offset"]
            reg["high"] = reg["low"] + reg["size"]

        self._registers[reg["name"]] = reg        

    def getParentRegister(self, register):
        if register["type_str"] == "flg":
            return             
            
        parents = {}
        high_size = 0
        for reg in self.reg_info:
            if reg["name"] == register["name"]:
                continue

            size = reg["size"]
            reg_start = reg["offset"]
            reg_end = reg_start + size

            if reg["type"] == register["type"] and size > register["size"]:
                if register["offset"] >= reg_start and (register["offset"] + register["size"]) <= reg_end:
                    parents[size] = reg
                    if size > high_size:
                        high_size = size

            elif reg["type"] == register["type"] and size == register["size"]:
                if register["offset"] == reg["offset"]:
                    if "bv" in reg:
                        #self.aliases[register["name"]] = {"reg": reg["name"]}

                        parents[size] = reg
                        if size > high_size:
                            high_size = size

        # the largest reg is the parent
        if high_size != 0:
            parent = parents[high_size]
            self.parent_dict[register["name"]] = parent["name"]
            return parent

    def getParentName(self, name):
        if name in self.parent_dict:
            return self.parent_dict[name]
        else:
            return name

    def __getitem__(self, key):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]

        if register["parent"] == None:
            return register["bv"]
        
        else:
            parent = self._registers[register["parent"]]

            if parent["size"] == register["size"]:
                return parent["bv"]

            reg = solver.Extract(register["high"], register["low"], parent["bv"])
            #setRegisterName(reg, key)
            return reg

    def __setitem__(self, key, val):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        reg_name = self.getParentName(key)
        register = self._registers[reg_name]["bv"]

        if type(val) == int:
            new_reg = solver.BitVecVal(val, register.size())

        elif type(val) in [solver.IntNumRef, solver.ArithRef]:
            new_reg = solver.Int2BV(val, register.size())
            
        elif type(val) in [solver.BitVecNumRef, solver.BitVecRef]:
            szdiff = register.size() - val.size()
            if szdiff > 0:
                new_reg = solver.Concat(solver.BitVecVal(0, szdiff), deepcopy(val))

            elif szdiff < 0:
                new_reg = solver.Extract(register.size()-1, 0, deepcopy(val))
            else:
                new_reg = deepcopy(val)

        else:
            raise ESILArgumentException

        # added the simplify here... 
        # idk if this actually will create any performance improvements
        # but it will be better for debugging output maybe?
        # or it will be worse?
        self._registers[reg_name]["bv"] = solver.simplify(new_reg)

    def __contains__(self, key):
        return self._registers.__contains__(key)
