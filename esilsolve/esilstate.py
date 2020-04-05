from . import solver
from .esilclasses import *
from .esilregisters import *
from .esilmemory import *
from .esilprocess import *
import copy

class ESILState:
    
    def __init__(self, r2api, opt=False, init=True, debug=False, trace=False, sym=False):
        self.r2api = r2api
        self.pure_symbolic = sym

        if opt:
            self.solver = solver.Optimize()
        else:
            self.solver = solver.SimpleSolver()

        self.model = None

        self.esil = {"cur":0, "old":0, "stack":[]}
        self.stack = self.esil["stack"]
        self.info = self.r2api.get_info()
        self.debug = debug
        self.trace = trace
        self.proc = ESILProcess(r2api, debug=debug, trace=trace)
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
            self.init_state()

    def init_state(self):
        # get information about the registers and memory
        self.init_registers()
        self.init_memory()

    def init_memory(self):
        self.memory = ESILMemory(self.r2api, self.info, self.pure_symbolic)
        self.memory.solver = self.solver
        self.memory.init_memory()

    def init_registers(self):
        self.register_info = self.r2api.get_register_info()
        self.aliases = {}
        registers = self.register_info["reg_info"]
        aliases = self.register_info["alias_info"]
        register_values = self.r2api.get_all_registers()

        for alias in aliases:
            self.aliases[alias["role_str"]] = alias

        for register in registers:
            register["value"] = register_values[register["name"]]

        self.registers = ESILRegisters(registers, self.aliases, sym=self.pure_symbolic) #reg_dict
        self.registers.init_registers()

    def set_symbolic_register(self, name):
        size = self.registers[name].size()
        self.registers[name] = solver.BitVec(name, size)

    def constrain_register(self, name, val):
        reg = self.registers[name]
        self.solver.add(reg == val)

    def evaluate_register(self, name, eval_type="eval"):
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

    def step(self):
        pc = self.registers["PC"].as_long() 
        instr = self.r2api.disass(pc)
        new_states = self.proc.execute_instruction(self, instr)
        return new_states

    def is_sat(self):
        if self.solver.check() == solver.sat:
            return True
        
        return False

    def clone(self):
        clone = self.__class__(self.r2api, init=False, sym=self.pure_symbolic, debug=self.debug, trace=self.trace)
        clone.stack = deepcopy(self.stack)
        clone.solver = deepcopy(self.solver)
        clone.proc = self.proc.clone()
        clone.steps = self.steps
        clone.bits = self.bits
        clone.aliases = self.aliases
        clone.registers = self.registers.clone()
        clone.memory = self.memory.clone()
        clone.memory.solver = clone.solver

        return clone

class ESILStateManager:

    def __init__(self, active=[], avoid=[]):
        self.active = set(active)
        self.inactive = set()
        self.unsat = set()
        self.recently_added = set()

        if isinstance(avoid, int):
            avoid = (avoid,)

        self.avoid = avoid

    def next(self):
        #print(self.active)
        #print(self.inactive)
        if len(self.active) > 32:
            state = max(self.active, key=lambda s: s.steps)
        else:
            state = min(self.active, key=lambda s: s.steps)

        self.active.discard(state)
        return state

    def add(self, state):
        pc = state.registers["PC"]
        if solver.is_bv_value(pc):
            if pc.as_long() in self.avoid:
                self.inactive.add(state)

            else:
                self.active.add(state)

        elif state.is_sat():
            self.active.add(state)

        else:
            self.unsat.add(state)

    def entry_state(self, r2api, optimize=False, sym=False, debug=False, trace=False):
        state = ESILState(r2api, opt=optimize, sym=sym, debug=debug, trace=trace)
        self.add(state)
        return state