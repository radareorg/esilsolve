from .r2api import R2API
from . import solver
from .esilclasses import * 
from .esilstate import ESILState, ESILStateManager
from .esilprocess import ESILProcess

import multiprocessing
import logging

class ESILSolver:
    def __init__(self, r2p=None, init=False, optimize=False, debug=False, trace=False, sym=False):
        self.debug = debug
        self.trace = trace
        self.states = []
        self.hooks = {}
        self.state_manager = None
        self.pure_symbolic = sym

        self.conditionals = {}
        self.cond_count = 0
        self.optimize = optimize

        if r2p == None:
            r2api = R2API()
        else:
            r2api = R2API(r2p)

        self.r2api = r2api
        self.did_init_vm = False
        self.info = self.r2api.get_info()
        self.processes = []

        if init:
            self.init_state()

    # initialize the ESIL VM
    def init_vm(self):
        self.r2api.init_vm()
        self.did_init_vm = True

    def run(self, target=None, avoid=[], procs=1):
        self.r2api.disass(instrs=128) # cache instrs for performance

        found = False
        self.state_manager.avoid = avoid

        while not found:
            state = self.state_manager.next()

            pc = state.registers["PC"].as_long() 

            if target != None:
                state.distance = abs(target-pc)

            instr = self.r2api.disass(pc)
            found = pc == target
        
            if pc in self.hooks:
                for hook in self.hooks[pc]:
                    hook(instr, state)

            if not found:
                new_states = state.proc.execute_instruction(state, instr)
                for new_state in new_states:
                    self.state_manager.add(new_state)
            else:
                self.state_manager.add(state)
                return state

    def register_hook(self, addr, func):
        if addr in self.hooks:
            self.hooks[addr].append(func)
        else:
            self.hooks[addr] = [func]

    def init_state(self):
        self.state_manager = ESILStateManager([])
        state = self.state_manager.entry_state(self.r2api, self.optimize, self.pure_symbolic, self.debug, self.trace)
        return state

    def blank_state(self, addr=0):
        self.state_manager = ESILStateManager([])
        state = self.state_manager.entry_state(self.r2api, self.optimize, True, self.debug, self.trace)
        state.registers["PC"] = solver.BitVecVal(addr, state.registers["PC"].size())
        return state