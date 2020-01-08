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
                self.executeInstruction(state, instr)
                state.steps += 1
            else:
                self.state_manager.add(state)
                return state

    def initState(self):
        state = ESILState(self.r2api, opt=self.optimize, self.debug, self.trace)
        #self.states.append(state)
        self.state_manager = ESILStateManager([state])
        return state

