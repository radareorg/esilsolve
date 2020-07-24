
from .esilclasses import *
import z3

class ESILRegisters:
    def __init__(self, reg_array, aliases={}, sym=False):
        self.reg_info = reg_array
        self._registers = {}
        self.offset_dictionary = {}
        self._register_values = {}
        self.aliases = aliases
        self._refs = {"count": 1}

        self.pure_symbolic = sym

    def init_registers(self):
        self.reg_info.sort(key=lambda x: x["size"], reverse=True)
        for reg in self.reg_info:
            self.add_register(reg)

    def add_register(self, reg):
        start = reg["offset"]
        end = reg["offset"] + reg["size"]
        size = reg["size"]

        reg["start"] = start
        reg["end"] = end
        self._registers[reg["name"]] = reg    

        # if its a *flags reg treat it special
        # this will be a perf improvement
        #if reg["type_str"] == "flg" and size > 1:
        #    return 

        key = (start, end)

        reg_value = self.get_register_from_bounds(reg)

        if reg_value != None:
            # this shouldnt happen idk
            if reg_value["size"] < size:
                reg_value["size"] = size
                reg_value["start"] = start
                reg_value["end"] = end

                if self.pure_symbolic and reg["name"] != self.aliases["PC"]["reg"] and reg["type_str"] != "flg":
                    reg.pop("value")
                    reg_value["bv"] = z3.BitVec(reg["name"], size)
                else:
                    reg_value["bv"] = z3.BitVecVal(reg.pop("value"), size)

                reg_value["bounds"] = key
                self.offset_dictionary[key] = reg_value

            reg["bounds"] = reg_value["bounds"]
            reg["sub"] = True

        else:
            reg_value = {"type": reg["type"], "size": size, "start": start, "end": end}
            if "value" in reg and (not self.pure_symbolic or reg["name"] == self.aliases["PC"]["reg"] or reg["type_str"] == "flg"):
                reg_value["bv"] = z3.BitVecVal(reg.pop("value"), size)
            else:
                reg.pop("value")
                reg_value["bv"] = z3.BitVec(reg["name"], size) 

            reg_value["bounds"] = key
            self.offset_dictionary[key] = reg_value

            reg["bounds"] = key
            reg["sub"] = False
            
    def get_register_from_bounds(self, reg):

        if "bounds" in reg and reg["bounds"] in self.offset_dictionary:
            return self.offset_dictionary[reg["bounds"]]

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

                above_start = (bounds[0] <= start <= bounds[1])
                below_end = (bounds[0] <= end <= bounds[1])

                if above_start and below_end:
                    return old_reg

    def __getitem__(self, key):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]
        reg_value = self.get_register_from_bounds(register)

        if register["size"] == reg_value["size"]:
            return reg_value["bv"]

        else:
            low = register["start"] - reg_value["start"]
            high = low + register["size"]
            reg = z3.Extract(high-1, low, reg_value["bv"])
            return reg

    def __setitem__(self, key, val):

        if self._refs["count"] > 1:
            self.finish_clone()

        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]
        reg_value = self.get_register_from_bounds(register)

        # idk this should be fine and its faster but gives complex answers
        if False and z3.is_bv(val) and val.size() == reg_value["size"]:
            reg_value["bv"] = z3.simplify(val)

        else:
            zero = z3.BitVecVal(0, reg_value["size"])
            new_reg = self.set_register_bits(register, reg_value, zero, val)
            reg_value["bv"] = z3.simplify(new_reg)

    def weak_set(self, key, val):
        
        if self._refs["count"] > 1:
            self.finish_clone()

        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]

        # this gets the full register bv not the subreg bv
        reg_value = self.get_register_from_bounds(register)
        new_reg = self.set_register_bits(register, reg_value, reg_value["bv"], val)
        reg_value["bv"] = z3.simplify(new_reg)

    def val_to_register_bv(self, reg, val):
        new_val = val

        if type(val) == int:
            new_val = z3.BitVecVal(val, reg["size"])

        elif z3.is_int(val):
            new_val = z3.Int2BV(val, reg["size"])

        elif z3.is_bv(val):
            if val.size() > reg["size"]:
                new_val = z3.Extract(reg["size"]-1, 0, val)
            elif val.size() < reg["size"]:
                new_val = z3.ZeroExt(reg["size"]-val.size(), val)
            else:
                new_reg = val

        else:
            raise ESILArgumentException

        return new_val

    def set_register_bits(self, register, reg_value, bv, val):
        low = register["start"] - reg_value["start"]
        high = low + register["size"]        

        bvs = []

        if high != reg_value["size"]:
            upper = z3.Extract(reg_value["size"]-1, high, bv)
            bvs.append(upper)

        bvs.append(self.val_to_register_bv(register, val))
        
        if low != 0:
            lower = z3.Extract(low-1, 0, bv)
            bvs.append(lower)

        if len(bvs) > 1:
            new_reg = z3.Concat(bvs)
        else:
            new_reg = bvs[0]

        return new_reg

    def __contains__(self, key):
        return self._registers.__contains__(key)

    def clone(self):
        clone = self.__class__(self.reg_info, self.aliases, self.pure_symbolic)
        self._refs["count"] += 1
        clone._refs = self._refs
        clone._registers = self._registers
        clone.offset_dictionary = self.offset_dictionary

        return clone

    def finish_clone(self):
        self.offset_dictionary = self.offset_dictionary.copy()
        for x in self.offset_dictionary:
            self.offset_dictionary[x] = self.offset_dictionary[x].copy()

        self._refs["count"] -= 1
        self._refs = {"count": 1}