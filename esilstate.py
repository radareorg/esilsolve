import solver
from esilclasses import *
from esilregisters import *
from esilmemory import *

class ESILState:
    
    def __init__(self, r2api, opt=False):
        self.r2api = r2api

        if opt:
            self.solver = solver.Optimize()
        else:
            self.solver = solver.Solver()

        self.model = None

        self.esil = {"cur":0, "old":0, "stack":[]}
        self.stack = self.esil["stack"]
        self.info = self.r2api.getInfo()
        self.memory = {}
        self.registers = {}
        self.aliases = {}

        if "info" in self.info:
            self.bits = self.info["info"]["bits"]
        else:
            self.bits = 64

        # get information about the registers and memory
        self.initRegisters()
        self.initMemory()

    def initMemory(self):
        self.memory = ESILMemory(self.r2api, self.info)

    def initRegisters(self):
        self.register_info = self.r2api.getRegisterInfo()
        self.aliases = {}
        registers = self.register_info["reg_info"]
        aliases = self.register_info["alias_info"]
        register_values = self.r2api.getAllRegisters()

        for alias in aliases:
            self.aliases[alias["role_str"]] = alias

        for register in registers:
            register["value"] = register_values[register["name"]]

        self.registers = ESILRegisters(registers, self.aliases) #reg_dict

    def setSymbolicRegister(self, name):
        size = self.registers[name].size()
        self.registers[name] = solver.BitVec(name, size)

    def constrainRegister(self, name, val):
        reg = self.registers[name]
        self.solver.add(reg == val)

    def evaluateRegister(self, name, eval_type="eval"):
        val = self.registers[name]

        if eval_type == "max":
            self.solver.maximize(val)
        elif eval_type == "min":
            self.solver.minimize(val)

        if self.model == None:
            sat = self.solver.check()
            
            if sat:
                self.model = self.solver.model()
            else:
                raise ESILUnsatException

        value = self.model.eval(val)

        return value

    def popAndEval(self):
        val = self.stack.pop()

        if type(val) == int:
            return val
            
        if self.model == None:
            sat = self.solver.check()
            if sat:
                self.model = self.solver.model()
            else:
                raise ESILUnsatException

        return self.model.eval(val)