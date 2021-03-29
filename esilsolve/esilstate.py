import z3
from .esilclasses import *
from .esilregisters import *
from .esilmemory import *
from .esilprocess import ESILProcess
from .esilfs import ESILFilesystem
from .esilos import ESILOS
from .r2api import R2API

import re # for buffer constraint

class ESILState:
    """
    A single possible state of the execution

    This contains all context of execution: memory, registers, constraints.
    All manipulation of a state should be done using the methods here 

    :param r2api:     Instance of the R2API for communicating with r2
    :param sym:       Boolean describing whether the state is blank 
    """
    
    def __init__(self, r2api: R2API, **kwargs):
        self.kwargs = kwargs
        self.r2api = r2api
        self.pure_symbolic = kwargs.get("sym", False)
        self.pcode = kwargs.get("pcode", False)
        self.check_perms = kwargs.get("check", False)

        if kwargs.get("optimize", False):
            self.solver = z3.Optimize()
        elif kwargs.get("simple", True):
            self.solver = z3.SimpleSolver()
        else:
            self.solver = z3.Solver()

        #self.solver.set("cache_all", True)

        timeout = kwargs.get("timeout", None)
        if timeout != None:
            self.solver.set("timeout", timeout)

        #self.solver.set("threads", 4)

        # without this push z3 does not use an "incremental" solver 
        # which causes it to try tactics which are wildly slow 
        self.solver.push() 

        #self.constraints = []
        self.model = None
        self.current_instruction = None

        self.esil = {
            "cur":0, "old":0, "stack":[],
            "size": 64, "type": 1
        }
        self.stack = self.esil["stack"]
        self.max_len = kwargs.get("max_len", 4096)

        self.pid = kwargs.get("pid", 1337)
        self.fork_mode = kwargs.get("fork_mode", "parent")

        # esilsolve aint sleepin
        self.sleep = kwargs.get("sleep", False)
        self.info = self.r2api.get_info()
        self.debug = kwargs.get("debug", False)
        self.trace = kwargs.get("trace", False)

        self.events = kwargs.get("events", {})

        self.memory: ESILMemory = None
        self.registers: ESILRegisters = None
        self.proc: ESILProcess = None
        self.fs: ESILFilesystem = None
        self.os: ESILOS = None

        self.condition = None

        # steps executed and distance from goal
        self.steps = 0
        self.distance = 0xffffffff
        self.target = None
        self.exit = None

        if "info" in self.info:
            self.bits = self.info["info"]["bits"]
            self.endian = self.info["info"]["endian"]
        else:
            self.bits = 64
            self.endian = "little"

        if kwargs.get("init", True):
            self.proc = ESILProcess(r2api, **kwargs)
            self.init_state()

    def init_state(self):
        # get information about the registers and memory
        self.init_registers()
        self.init_memory()
        self.init_filesystem()
        self.init_os()

        # this fuckin sucks
        flags = self.r2api.get_flags()
        stdfds = {
            "obj.stdin":  0,
            "obj.stdout": 1,
            "obj.stderr": 2
        }
        for stdfd in stdfds:
            if stdfd in flags:
                addr = flags[stdfd]["offset"]
                new_addr = self.memory.alloc()
                self.memory[new_addr] = stdfds[stdfd]
                self.memory[addr] = new_addr

    def init_memory(self):
        max_eval = self.kwargs.get("max_eval", 32)
        self.memory = ESILMemory(
            self.r2api, self.info, max_eval,
            self.pure_symbolic, self.check_perms)

        self.memory.solver = self.solver
        self.memory.max_len = self.max_len
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

        self.registers = ESILRegisters(
            registers, self.aliases, sym=self.pure_symbolic)

        self.registers.init_registers()

    def init_filesystem(self):
        self.fs = ESILFilesystem(self.r2api, **self.kwargs)

    def init_os(self):
        self.os = ESILOS(self.r2api, **self.kwargs)

    def dump_file(self, f):
        data = self.fs.content(f)
        if len(data) > 0:
            return self.memory.pack_bv(data)

    def dump_stdin(self):
        return self.dump_file(0)

    def dump_stdout(self):
        return self.dump_file(1)

    def dump_stderr(self):
        return self.dump_file(2)

    def write_stdin(self, data):
        self.fs.add({0: data})

    def set_symbolic_register(self, name: str, var: str = None):
        """
        Set a register to be a new symbolic value

        :param name:     Name of the register (ex. "rax") 
        :param var:      Variable name for the symbolic value
        """

        if var == None:
            var = name

        size = self.registers[name].size()
        self.registers[name] = z3.BitVec(var, size)

    def check_addr(self, bv, mode="r", length=None, data=None):

        if isinstance(bv, int):
            return
        elif z3.is_bv_value(bv):
            return

        bv = z3.simplify(bv)
        if z3.is_bv_value(bv):
            return 

        elif z3.is_bv(bv):

            mode_to_event = {
                "r": ESILSolveEvent.SymRead,
                "w": ESILSolveEvent.SymWrite,
                "x": ESILSolveEvent.SymExec,
                "f": ESILSolveEvent.SymFree
            }
            event = mode_to_event[mode]
            if event in self.events:
                # normalize everything to be bvs
                if isinstance(length, int):
                    length = BV(length, self.bits)

                if isinstance(data, list):
                    data = self.memory.pack_bv(data)

                ctx = EventContext(bv, length, data)
                for hook in self.events[event]:
                    hook(self, ctx)

    def mem_read(self, addr, length):
        self.check_addr(addr, "r", length)
        return self.memory.read(addr, length)

    def mem_write(self, addr, data):
        self.check_addr(addr, "w", data=data)
        return self.memory.write(addr, data)

    def mem_read_bv(self, addr, length):
        self.check_addr(addr, "r", length)
        return self.memory.read_bv(addr, length)

    def mem_cond_read(self, addr, length):
        self.check_addr(addr, "r", length)
        return self.memory.cond_read(addr, length)

    def mem_write_bv(self, addr, val, length):
        self.check_addr(addr, "w", length, val)
        return self.memory.write_bv(addr, val, length)

    def mem_copy(self, dst, data, length):
        self.check_addr(dst, "w", length, data)
        return self.memory.copy(dst, data, length)

    def mem_memcopy(self, src, dst, length):
        src = self.check_addr(src, "r", length)
        dst = self.check_addr(dst, "w", length)
        return self.memory.memcopy(src, dst, length)

    def mem_compare(self, src, dst, length=None):
        self.check_addr(src, "r", length)
        self.check_addr(dst, "w", length)
        return self.memory.compare(src, dst, length)

    def mem_move(self, src, dst, length):
        self.check_addr(src, "r", length)
        self.check_addr(dst, "w", length)
        return self.memory.move(src, dst, length)

    def mem_alloc(self, length=128):
        return self.memory.alloc(length)

    def mem_free(self, addr):
        self.check_addr(addr, "f")
        return self.memory.free(addr)

    def mem_search(self, addr, needle, length=None, reverse=None):
        self.check_addr(addr, "r")
        return self.memory.search(addr, needle, length, reverse)

    def constrain(self, *constraints):
        """ Add constraint to the state """

        #self.constraints.extend(constraints)
        self.solver.add(*constraints)

    # this bizarre function takes a regular expression like [A-Z 123]
    # and constrains all the bytes in the bv to fit the expression
    def constrain_bytes(self, bv, regex: Union[str, bytes]):

        # if its a bytes expr just constrain beginning to those values
        if type(regex) == bytes:
            for i in range(len(regex)):
                self.constrain(z3.Extract(7+i*8, i*8, bv) == regex[i])

            return 

        all_bytes = "".join([chr(x) for x in range(256)])

        if z3.is_bv(bv):
            bv = [z3.Extract(b*8+7, b*8, bv) for b in range(int(bv.size()/8))]

        # this is gross and could probably break
        opts = []
        new_regex = regex[:]
        negate = False
        if len(regex) > 2 and regex[:2] == "[^":
            negate = True
            new_regex = new_regex.replace("[^", "[")

        dashes = [i for i,c in enumerate(regex) if c == "-"]
        for d in dashes:
            if regex[d-1] != "\\" and len(regex) > d:
                x = ord(regex[d-1])
                y = ord(regex[d+1])
                opts.append([x, y])
                new_regex = new_regex.replace(regex[d-1:d+2], "")
        
        vals = []
        if new_regex != "[]":
            vals = [ord(x) for x in re.findall(new_regex, all_bytes, re.DOTALL)]
            
        for b in bv:
            or_vals = []
            for val in vals:
                or_vals.append(b == val)

            for opt in opts:
                or_vals.append(z3.And(b >= opt[0], b <= opt[1]))

            if negate:
                self.constrain(z3.Not(z3.Or(*or_vals)))
            else:
                self.constrain(z3.Or(*or_vals))

    def constrain_register(self, name: str, val):
        """ Constrain a register by name to a value """

        reg = self.registers[name]
        self.constrain(reg == val)

    def evaluate_register(self, name: str, eval_type: str="eval"):
        val = self.registers[name]

        if eval_type == "max":
            self.solver.maximize(val)
        elif eval_type == "min":
            self.solver.minimize(val)

        if self.model == None:
            sat = self.solver.check()
            
            if sat == z3.sat:
                self.model = self.solver.model()
            else:
                raise ESILUnsatException("state has unsatisfiable constraints")

        value = self.model.eval(val, True)
        return value

    def evaluate(self, val: z3.BitVecRef) -> int:
        """ 
        Evaluate value with the current states constraints 
        
        :param val:     Symbol to be evaluated
        """
        if self.is_sat():
            model = self.solver.model()
            return model.eval(val, True)
        else:
            raise ESILUnsatException("state has unsatisfiable constraints")

    # shortcut to eval + constrain
    def evalcon(self, val: z3.BitVecRef):
        eval_val = self.evaluate(val)
        self.constrain(val == eval_val)
        return eval_val

    def eval_max(self, sym, n: int = 64):
        solutions = []

        self.solver.push()
        while len(solutions) < n:
            if self.solver.check() == z3.sat:
                m = self.solver.model()
                sol = m.eval(sym, True)
                solutions.append(sol)
                self.solver.add(sym != sol)
            else:
                break

        self.solver.pop()
        return solutions

    def symbol(self, name: str, length: int, cons=None) -> z3.BitVecRef:
        bv = z3.BitVec(name, length*8)

        if cons != None:
            self.constrain_bytes(bv, cons)

        return bv

    def evaluate_buffer(self, bv: z3.BitVecRef) -> bytes:
        buf = self.evaluate(bv)
        val = buf.as_long()
        length = bv.size()//8
        return bytes([(val >> (8*i)) & 0xff for i in range(length)])

    def evaluate_string(self, bv: z3.BitVecRef) -> str:
        b = self.evaluate_buffer(bv)
        if b"\x00" in b:
            b = b[:b.index(b"\x00")]

        return b.decode()

    def symbolic_string(self, addr, length=None):
        ret_len, last = self.mem_search(addr, [BZERO], length)
        data = self.mem_read_bv(addr, last)
        return data, ret_len
        
    def concrete_string(self, addr, length=None):
        ret_len, last = self.memory.search(addr, [BZERO], length)
        sym_str = self.memory.read_bv(addr, last)
        self.evalcon(sym_str)
        return self.evaluate_string(sym_str)

    def step(self) -> List:
        """ Step the state forward by executing one instruction """

        pc = self.registers["PC"].as_long() 
        instr = self.r2api.disass(pc)
        self.current_instruction = instr
        new_states = self.proc.execute_instruction(self, instr)
        return new_states

    def is_sat(self) -> bool:
        """ Check whether the states constraints are satisfiable"""
        return self.solver.check() == z3.sat

    def apply(self):
        """ 
        Apply this state to the r2 instance 
        
        This method evaluates all the symbolic memory and register values
        and writes the results to the underlying r2 analyzing the binary
        """

        # apply registers
        for reg in self.registers._registers:
            if not self.registers._registers[reg]["sub"]:
                register = self.registers[reg]
                value = self.evaluate(register)
                self.constrain(register == value)
                self.r2api.set_reg_value(reg, value.as_long())

        # apply memory
        for addr in self.memory._memory:
            value_bv = self.evaluate(self.memory[addr])
            self.constrain(self.memory[addr] == value_bv)

            value = self.evaluate_buffer(self.memory[addr])
            length = self.memory[addr].size()//8

            self.r2api.write(addr, value, length)

    def clone(self) -> "ESILState":
        self.kwargs["init"] = False
        clone = self.__class__(
            self.r2api, 
            **self.kwargs
        )

        clone.constrain(*self.solver.assertions())

        clone.proc = self.proc #.clone() no need to clone this 
        clone.pid = self.pid
        clone.fork_mode = self.fork_mode
        clone.steps = self.steps
        clone.distance = self.distance
        clone.esil = self.esil.copy()
        clone.registers = self.registers.clone()
        clone.memory = self.memory.clone()
        clone.fs = self.fs.clone()
        clone.memory.solver = clone.solver

        return clone

class ESILStateManager:
    """
    Manage the status and order of the current states

    :param active:     The list of active states to begin with
    :param avoid:      List of addresses to avoid in execution
    :param lazy:       Do not check satisfiability of the states
    """

    def __init__(self, active: List[ESILState]=[], avoid=[], merge=[], lazy=False):
        self.active = set(active)
        self.inactive = set()
        self.unsat = set()
        self.merged = set()
        self.recently_added = set()
        self.exited = set()

        if isinstance(avoid, int):
            avoid = [avoid]

        if isinstance(merge, int):
            merge = [merge]

        self.avoid = avoid
        self.merge = merge
        self.merge_states = {}
        self.cutoff = 32

        self.merge_counts = {}
        self.max_merges = 65536

        self.lazy = lazy

    def next(self) -> ESILState:
        """ Get the next state to be stepped """

        if len(self.active) == 0:
            if len(self.merged) == 0:
                return

            state = max(self.merged, key=lambda s: s.steps)
            self.merged.discard(state)
            self.merge_states.pop(state.registers["PC"].as_long()) 
            return state

        elif len(self.active) > self.cutoff:
            state = max(self.active, key=lambda s: s.steps)
        else:
            state = min(self.active, key=lambda s: s.steps)
            #state = min(self.active, key=lambda s: s.distance) 

        self.active.discard(state)
        return state

    def add(self, state: ESILState):
        """
        Add state to the manager

        :param state:     The state to be added 
        """

        pc = state.registers["PC"]
        if z3.is_bv_value(pc):
            pc = pc.as_long()
            if pc in self.avoid:
                self.inactive.add(state)
            else:
                if pc in self.merge:
                    self.merge_state(state)
                else:
                    self.active.add(state)

        elif self.lazy or state.is_sat():
            self.active.add(state)

        else:
            self.unsat.add(state)

    def entry_state(self, r2api: R2API, **kwargs) -> ESILState:
        """
        Get an initial state

        :param r2api:     Instance of R2API to communicate with r2
        """
        
        state = ESILState(r2api, **kwargs)
        self.add(state)
        return state

    def merge_state(self, state: ESILState):
        """
        Merge the states at the provided points
        TODO: use backtraces to prevent undesired merges
        """

        pc = state.registers["PC"].as_long()

        if pc not in self.merge_states:
            self.merge_states[pc] = state
           
            if pc not in self.merge_counts:
                self.merge_counts[pc] = 0

            self.merged.add(state)
            return

        merged = self.merge_states[pc]
        self.merge_counts[pc] += 1
        assertion = z3.And(*state.solver.assertions())

        # merge the regs
        for bounds in merged.registers.offset_dictionary:
            merge_val = merged.registers.offset_dictionary[bounds]
            state_val = state.registers.offset_dictionary[bounds]

            if not z3.eq(merge_val["bv"], state_val["bv"]):
                merge_val["bv"] = z3.If(assertion, 
                    state_val["bv"], merge_val["bv"])

        # merge the memory
        addrs = set(list(merged.memory)+list(state.memory))
        for addr in addrs:
            if not z3.eq(merged.memory[addr], state.memory[addr]):
                merged.memory[addr] = z3.If(assertion, 
                    state.memory[addr], merged.memory[addr])

        # merge solvers 
        combined = z3.Or(
            z3.And(*merged.solver.assertions()), assertion)

        merged.solver.reset()
        merged.solver.add(combined)
        merged.steps = max(merged.steps, state.steps)

        if self.merge_counts[pc] < self.max_merges:
            self.merged.add(merged)
        else:
            # kick it out of merging
            self.merged.discard(merged)
            self.merge_states.pop(pc)
            self.active.add(merged)

    def exit(self, state):
        self.exited.add(state)