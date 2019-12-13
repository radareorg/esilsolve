import solver
from esilclasses import *
from esilregisters import *
from esilmemory import *
import copy

class ESILState:
    
    def __init__(self, r2api, opt=False, init=True):
        self.r2api = r2api

        if opt:
            self.solver = solver.Optimize()
        else:
            self.solver = solver.SimpleSolver()

        self.model = None

        self.esil = {"cur":0, "old":0, "stack":[]}
        self.stack = self.esil["stack"]
        self.info = self.r2api.getInfo()
        self.memory = {}
        self.registers = {}
        self.aliases = {}
        self.condition = None
        self.steps = 0

        if "info" in self.info:
            self.bits = self.info["info"]["bits"]
        else:
            self.bits = 64

        if init:
            self.initState()

    def initState(self):
        # get information about the registers and memory
        self.initRegisters()
        self.initMemory()

    def initMemory(self):
        self.memory = ESILMemory(self.r2api, self.info)
        self.memory.initMemory()

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
        self.registers.initRegisters()

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
            
            if sat == solver.sat:
                self.model = self.solver.model()
            else:
                raise ESILUnsatException

        value = self.model.eval(val)

        return value

    def concretize(self, val):
        if self.model == None:
            sat = self.solver.check()
            
            if sat == solver.sat:
                self.model = self.solver.model()
            else:
                raise ESILUnsatException

        value = self.model.eval(val)

        return value

    def isSat(self):
        if self.solver.check() == solver.sat:
            return True
        
        return False

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

    def clone(self):
        clone = self.__class__(self.r2api, init=False)
        clone.stack = copy.deepcopy(self.stack)
        clone.solver = copy.deepcopy(self.solver)
        clone.steps = self.steps
        clone.bits = self.bits
        clone.aliases = copy.deepcopy(self.aliases)
        clone.registers = self.registers.clone()
        clone.memory = self.memory.clone()

        return clone

class ESILStateManager:

    def __init__(self, active=[], avoid=None):
        self.active = set(active)
        self.inactive = set()
        self.unsat = set()
        self.recently_added = set()

        if isinstance(avoid, int):
            avoid = (avoid,)

        self.avoid = avoid

    def next(self):
        #print(self.active)
        #print(self.unsat)
        if len(self.active) > 32:
            state = max(self.active, key=lambda s: s.steps)
        else:
            state = min(self.active, key=lambda s: s.steps)

        self.active.discard(state)
        return state

    def add(self, state):
        pc = solver.simplify(state.registers["PC"])
        #print(pc)
        if solver.is_bv_value(pc):
            if pc.as_long() in self.avoid:
                self.inactive.add(state)

            else:
                self.active.add(state)

        elif state.isSat():
            self.active.add(state)

        else:
            self.unsat.add(state)
