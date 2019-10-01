
from esilclasses import *
import solver

class ESILRegisters(dict):
    def __init__(self, reg_array, aliases={}):
        self.reg_info = reg_array
        self._registers = {}
        self.aliases = aliases

        self.parent_dict = {}

        for reg in reg_array:
            self.processRegister(reg)

    def processRegister(self, reg):
        parentRegister = self.getParentRegister(reg)

        if parentRegister == None:
            # register is not a subregister, give it a BV
            reg["parent"] = None

            if "value" in reg:
                reg["bv"] = newRegister(reg["name"], reg["size"], reg.pop("value"))

        else:
            reg["parent"] = parentRegister["name"]
            reg["low"] = reg["offset"] - parentRegister["offset"]
            reg["high"] = reg["low"] + reg["size"]

        self._registers[reg["name"]] = reg        

    def getParentRegister(self, register):
        parents = {}
        high_size = 0
        for reg in self.reg_info:
            size = reg["size"]
            reg_start = reg["offset"]
            reg_end = reg_start + size

            if reg["type"] == register["type"] and size > register["size"]:
                if register["offset"] >= reg_start and (register["offset"] + register["size"]) <= reg_end:
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
            return solver.Extract(register["high"], register["low"], parent["bv"])

    def __setitem__(self, key, value):
        if key in self.aliases:
            key = self.aliases[key]["reg"]

        register = self._registers[key]

        if register["parent"] == None:
            self._registers[key]["bv"] = value

        else:
            raise ESILArgumentException

    def __contains__(self, key):
        return self._registers.__contains__(key)

# this is gross but i dont want to have to wrap
# every single bv operation so...
def setRegisterName(bv, name):
    BVD(bv)["register"] = name

def getRegisterName(bv):
    return BVD(bv)["register"]

def setRegisterValue(reg_val, val, context):
    name = getRegisterName(reg_val)
    reg_name = context["registers"].getParentName(name)
    register = context["registers"][reg_name]

    if type(val) == int:
        new_reg = newRegister(reg_name, register.size(), val)
    elif type(val) in [solver.BitVecNumRef, solver.BitVecRef]:
        new_reg = deepcopy(val) 
        setRegisterName(new_reg, name)
    else:
        raise ESILArgumentException

    context["registers"][reg_name] = new_reg

def newRegister(name, size, val=None):
    if val != None:
        new_reg = solver.BitVecVal(val, size)
    else:
        new_reg = solver.BitVec(name, size)

    setRegisterName(new_reg, name)
    return new_reg