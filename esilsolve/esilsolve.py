import z3
from .r2api import R2API
from .esilclasses import * 
from .esilstate import ESILState, ESILStateManager
from .esilsim import ESILSim

from typing import Union, List

class ESILSolver:
    def __init__(self, r2p=None, **kwargs):
        self.kwargs = kwargs
        self.debug = kwargs.get("debug", False)
        self.trace = kwargs.get("trace", False)
        self.lazy = kwargs.get("lazy", False)
        self.states = []
        self.hooks = {}
        self.sims = {}
        self.state_manager = None
        self.pure_symbolic = kwargs.get("sym", False)

        self.conditionals = {}
        self.cond_count = 0
        self.optimize = kwargs.get("optimize", False)

        # use r2api which caches some data
        # to increase speed
        if r2p == None:
            r2api = R2API()
        else:
            if type(r2p) == str:
                r2api = R2API(filename=r2p)
            else:
                r2api = R2API(r2p)

        self.r2api = r2api
        self.r2pipe = r2api.r2p
        self.z3 = z3
        
        self.did_init_vm = False
        self.info = self.r2api.get_info()
        self.stop = False

        # context for hook variables
        # not really necessary yet since its single threaded
        # but we must look to the future
        self.context = {}

        if kwargs.get("init", False):
            self.init_state()

    # initialize the ESIL VM
    def init_vm(self):
        self.r2api.init_vm()
        self.did_init_vm = True

    def run(self, target=None, avoid=[]):
        self.stop = False

        # try to avoid leaving valid context when nothing is set
        if avoid == [] and self.state_manager.avoid == []:
            state = self.state_manager.next()
            avoid = self.default_avoid(state)

            # no target or hooks, target is last ret
            if target == None and avoid != []:
                if len(self.hooks) == 0:
                    target = avoid[-1]
                    avoid = avoid[:-1]
            
            if target in avoid:
                avoid.remove(target)

            self.state_manager.add(state)

        self.state_manager.avoid = avoid

        if type(target) == str:
            target = self.r2api.get_address(target)

        while not self.stop:
            state = self.state_manager.next()
            if state == None:
                return

            pc = state.registers["PC"].as_long() 

            state.target = target
            instr = self.r2api.disass(pc)
            found = pc == target
            if found:
                self.terminate()
        
            if pc in self.hooks:
                for hook in self.hooks[pc]:
                    hook(state)

            if instr["type"] == "call":
                if instr["jump"] in self.sims:
                    self.call_sim(state, instr)

            if not self.stop:
                new_states = state.step()
                for new_state in new_states:
                    self.state_manager.add(new_state)
            else:
                self.state_manager.add(state)
                return state

    def terminate(self):
        self.stop = True

    # get rets from initial state to stop at
    def default_avoid(self, state):
        pc = state.registers["PC"].as_long() 
        func = self.r2api.function_info(pc)
        instrs = self.r2api.disass_function(pc)

        rets = []
        for instr in instrs:
            if instr["type"] == "ret":
                rets.append(instr["offset"])

        return rets

    def register_hook(self, addr, func):
        if addr in self.hooks:
            self.hooks[addr].append(func)
        else:
            self.hooks[addr] = [func]

    def register_sim(self, func, hook):
        addr = self.r2api.get_address(func)
        self.sims[addr] = hook

    def call_sim(self, state, instr):
        target = instr["jump"]
        sim = self.sims[target](state)
        arg_count = sim.arg_count()
        bits = state.bits

        cc = self.r2api.calling_convention(target)
        args = []
        if "args" in cc:
            # register args
            for i in range(arg_count):
                arg = cc["args"][i]
                if arg in state.registers:
                    args.append(state.registers[arg])
        else:
            # read from stack
            sp = state.registers["SP"].as_long()
            for i in range(arg_count):
                addr = sp + int(i*bits/8)
                args.append(state.memory[addr])


        state.registers[cc["ret"]] = sim(*args)
        # fail contains next instr addr
        state.registers["PC"] = instr["fail"]
        
    def call_state(self, function):
        # seek to function and init vm
        self.r2api.seek(function)
        self.init_vm()
        return self.init_state()

    def reset(self, state):
        self.state_manager = ESILStateManager([], lazy=self.lazy)
        
        if state == None:
            state = self.state_manager.entry_state(self.r2api, **self.kwargs)
        else:
            self.state_manager.add(state)

    def init_state(self):
        self.state_manager = ESILStateManager([], lazy=self.lazy)
        state = self.state_manager.entry_state(self.r2api, **self.kwargs)
        return state

    def blank_state(self, addr=0):
        self.state_manager = ESILStateManager([], lazy=self.lazy)
        state = self.state_manager.entry_state(self.r2api, **self.kwargs)
        pc_size = state.registers["PC"].size()
        state.registers["PC"] = z3.BitVecVal(addr, pc_size)
        return state