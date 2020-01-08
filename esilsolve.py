from r2api import R2API
import solver
import esilops
import json
from esilclasses import * 
from esilstate import *
from esilprocess import *
import re

import logging

class ESILSolver:
    def __init__(self, r2p=None, init=False, optimize=False, debug=False, trace=False):
        self.debug = debug
        self.trace = trace
        self.states = []
        self.hooks = {}
        self.statemanager = None

        self.conditionals = {}
        self.cond_count = 0
        self.optimize = optimize

        if r2p == None:
            r2api = R2API()
        else:
            r2api = R2API(r2p)

        self.r2api = r2api
        self.didInitVM = False
        self.info = self.r2api.getInfo()

        if init:
            self.initState()

    # initialize the ESIL VM
    def initVM(self):
        self.r2api.initVM()
        self.didInitVM = True

    def run(self, target=None, avoid=[]):

        found = False
        self.state_manager.avoid = avoid

        while not found:
            #for state in states:
            state = self.state_manager.next()

            pc = state.registers["PC"].as_long() 

            instr = self.r2api.disass(pc)
            found = pc == target
        
            if pc in self.hooks:
                for hook in self.hooks[pc]:
                    hook(instr, state)

            if not found:
                new_states = state.proc.executeInstruction(state, instr)
                for new_state in new_states:
                    self.state_manager.add(new_state)
            else:
                self.state_manager.add(state)
                return state

    def registerHook(self, addr, func):
        if addr in self.hooks:
            self.hooks[addr].append(func)
        else:
            self.hooks[addr] = [func]

    def initState(self):
        self.state_manager = ESILStateManager([])
        state = self.state_manager.entryState(self.r2api, self.optimize)
        return state

