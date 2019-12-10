
from esilclasses import *
import solver


class ESILRegisters(dict):
    def __init__(self, reg_array, aliases={}):
        self.reg_info = reg_array
        self._registers = {}
        self.offset_dictionary = {}
        self.aliases = aliases

        self.parent_dict = {}
        self.super = None

        # sort reg array, this is important?
        reg_array.sort(key=lambda x: x["size"], reverse=True)
        #print(reg_array)

        for reg in reg_array:
            self.addRegister(reg)

    def addRegister(self, reg):
        start = reg["offset"]
        end = reg["offset"] + reg["size"]
        size = reg["size"]

        reg["start"] = start
        reg["end"] = end
        self._registers[reg["name"]] = reg    

        # if its a *flags reg treat it special
        # this will be a perf improvement
        if reg["type_str"] == "flg" and size > 1:
            return 

        key = (start, end)

        reg_value = self.getRegisterFromBounds(reg)

        if reg_value != None:
            if reg_value["size"] < size:
                reg_value["size"] = size
                reg_value["start"] = start
                reg_value["end"] = end
                reg_value["bv"] = solver.BitVecVal(reg.pop("value"), size)

                self.offset_dictionary[key] = reg_value

        else:
            reg_value = {"type": reg["type"], "size": size, "start": start, "end": end}
            if "value" in reg:
                reg_value["bv"] = solver.BitVecVal(reg.pop("value"), size)

            self.offset_dictionary[key] = reg_value
            
    def getRegisterFromBounds(self, reg):
        start = reg["offset"]
        end = reg["offset"] + reg["size"]
        size = reg["size"]

        key = (start, end)

        if key in self.offset_dictionary:
            return self.offset_dictionary[key]

        else:
            for bounds in self.offset_dictionary:
                old_reg = self.offset_dictionary[bounds]

                if old_reg["type"] != reg["type"]:
                    continue

                above_start = (bounds[0] <= start and start <= bounds[1])
                below_end = (bounds[0] <= end and end <= bounds[1])

                if above_start and below_end:
                    return old_reg

    def __getitem__(self, key):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]

        reg_value = self.getRegisterFromBounds(register)

        if register["size"] == reg_value["size"]:
            return reg_value["bv"]

        else:
            low = register["start"] - reg_value["start"]
            high = low + register["size"]
            reg = solver.Extract(high-1, low, reg_value["bv"])
            return reg

    def __setitem__(self, key, val):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]

        reg_value = self.getRegisterFromBounds(register)

        zero = solver.BitVecVal(0, reg_value["size"])
        new_reg = self.setRegisterBits(register, reg_value, zero, val)

        # added the simplify here... 
        # idk if this actually will create any performance improvements
        # but it will be better for debugging output maybe?
        # or it will be worse?
        reg_value["bv"] = solver.simplify(new_reg)
        
    def weakSet(self, key, val):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]

        # this gets the full register bv not the subreg bv
        reg_value = self.getRegisterFromBounds(register)

        new_reg = self.setRegisterBits(register, reg_value, reg_value["bv"], val)

        reg_value["bv"] = solver.simplify(new_reg)

    def valToRegisterBV(self, reg, val):
        new_val = val

        if type(val) == int:
            new_val = solver.BitVecVal(val, reg["size"])

        elif type(val) in [solver.IntNumRef, solver.ArithRef]:
            new_val = solver.Int2BV(val, reg["size"])

        elif type(val) in [solver.BitVecNumRef, solver.BitVecRef]:
            if val.size() > reg["size"]:
                new_val = solver.Extract(reg["size"]-1, 0, val)
            elif val.size() < reg["size"]:
                new_val = solver.Concat(solver.BitVecVal(0, reg["size"]-val.size()), val)
            else:
                new_reg = val

        else:
            raise ESILArgumentException

        return new_val

    def setRegisterBits(self, register, reg_value, bv, val):
        low = register["start"] - reg_value["start"]
        high = low + register["size"]

        bvs = []

        if high != reg_value["size"]:
            upper = solver.Extract(reg_value["size"]-1, high, bv)
            bvs.append(upper)

        bvs.append(self.valToRegisterBV(register, val))
        
        if low != 0:
            lower = solver.Extract(low-1, 0, bv)
            bvs.append(lower)

        if len(bvs) > 1:
            new_reg = solver.Concat(bvs)
        else:
            new_reg = bvs[0]

        return new_reg

    def __contains__(self, key):
        return self._registers.__contains__(key)
