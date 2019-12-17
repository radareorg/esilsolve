from r2api import R2API
import solver
import esilops
import json
from esilclasses import * 
from esilregisters import *
from esilmemory import *
from esilstate import *
import re

import logging

class ESILWord:
    def __init__(self, word=None, state=None):
        self.word = word
        self.len = len(word)

        if state != None:
            self.state = state
            self.bits = state.info["info"]["bits"]

            self.registers = state.registers
            self.memory = state.memory
    
    def isIf(self):
        return (self.len > 0 and self.word[0] == "?")

    def isElse(self):
        return (self.word == "}{")

    def isEndIf(self):
        return (self.word == "}")

    def isOperator(self):
        return (self.word in esilops.opcodes)

    def isLiteral(self):
        if (self.word.isdigit() or (self.len > 2 and self.word[:2] == "0x")):
            return True
        elif self.len > 1 and self.word[0] == "-" and self.word[1:].isdigit():
            return True
        else: 
            return False

    def isRegister(self):
        return (self.word in self.registers)

    def getRegister(self):
        #register = self.registers[self.word]
        return self.word

    def getLiteralValue(self):
        if(self.word.isdigit()):
            return int(self.word)
        elif self.len > 2 and self.word[:2] == "0x":
            return int(self.word, 16)
        elif self.len > 1 and self.word[0] == "-" and self.word[1:].isdigit():
            return int(self.word)

    def getPushValue(self):
        if(self.isLiteral()):
            val = self.getLiteralValue()
            return val

        elif(self.isRegister()):
            return self.getRegister()

        else:
            raise esilops.ESILUnimplementedException

    def doOp(self, stack):
        op = esilops.opcodes[self.word]
        op(self.word, stack, self.state)


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
    
    def executeInstruction(self, state, instr):
        if self.debug:
            print("\nexpr: %s" % instr["esil"])
            print("%016x: %s" % (instr["offset"], instr["opcode"]))

        # old pc should never be anything other than a BitVecVal
        old_pc = state.registers["PC"].as_long() 
        self.parseExpression(instr["esil"], state)

        pc = state.registers["PC"]
        if solver.is_bv_value(pc):
            new_pc = pc.as_long()

            if new_pc == old_pc:
                state.registers["PC"] = old_pc + instr["size"]

            if self.trace:
                self.r2api.emustep()
                self.traceRegisters(state)

            self.state_manager.add(state)
        else:
            # symbolic pc value
            if self.debug:
                print("symbolic pc: %s" % str(pc))

            possible_pcs = solver.eval_max(state.solver, pc)

            for possible_pc in possible_pcs:
                #print(possible_pc)

                if len(possible_pcs) > 1:
                    new_state = state.clone()
                else:
                    new_state = state

                new_state.solver.add(pc == possible_pc)
                if solver.simplify(possible_pc).as_long() == old_pc:
                    new_state.registers["PC"] = possible_pc + instr["size"]
                else:
                    new_state.registers["PC"] = possible_pc

                self.state_manager.add(new_state)

            #new_pc = state.concretize(pc).as_long()

    def registerHook(self, addr, func):
        if addr in self.hooks:
            self.hooks[addr].append(func)
        else:
            self.hooks[addr] = [func]

    def initState(self):
        state = ESILState(self.r2api, opt=self.optimize)
        #self.states.append(state)
        self.state_manager = ESILStateManager([state])
        return state

    def parseExpression(self, expression, state):

        temp_stack1 = None
        temp_stack2 = None
        exec_type = None
        expression = expression.replace("|=}", "|=,}") # typo fix
        words = expression.split(",")

        for word_str in words:
            word = ESILWord(word_str, state)

            if word.isIf():
                state.condition = self.doIf(word, state)
                exec_type = "IF"
                temp_stack1 = state.stack
                state.stack = []

            elif word.isElse():
                state.condition = solver.Not(state.condition)
                exec_type = "ELSE"
                temp_stack2 = state.stack
                state.stack = []
                
            elif word.isEndIf():
                # this code is weird and i dont like it
                # but its just necessary to do in some way
                if exec_type == "ELSE":
                    state.stack.reverse()
                    temp_stack2.reverse()

                    while len(state.stack) > 0:
                        if_val = esilops.popValue(temp_stack2, state)
                        else_val = esilops.popValue(state.stack, state)
                        #print(if_val, else_val)
                        condval = solver.If(state.condition, else_val, if_val)
                        temp_stack1.append(solver.simplify(condval))
                        #temp_stack1.append(condval)
                else:
                    temp_stack1 += state.stack

                state.condition = None
                exec_type = None
                state.stack = temp_stack1

            else:
                if word.isOperator():
                    word.doOp(state.stack)
                else:
                    val = word.getPushValue()
                    state.stack.append(val)

        
    def doIf(self, word, state):
        val = esilops.popValue(state.stack, state)
        if self.debug:
            print("condition val: %s" % val)

        zero = 0
        if solver.is_bv(val):
            zero = solver.BitVecVal(0, val.size())

        return val != zero

    def doIfOld(self, word, state):
        val = state.stack.pop()

        # this should not be necessary but it is
        # i really need to figure out what is happening here
        print(val)
        zero = 0
        if solver.is_bv(val):
            #zero = solver.BitVecVal(0, val.size())
            val = solver.BV2Int(val)
        
        state.solver.push()
        cond = val == zero
        state.solver.add(cond)
        sat = state.solver.check()
        
        if sat == solver.sat:
            return False

        state.solver.pop()
        cond = val != zero
        state.solver.add(cond)    
        return True

    def traceRegisters(self, state):
        for regname in state.registers._registers:
            register = state.registers._registers[regname]
            #print(regname, reg_value)
            if register["type_str"] in ["gpr", "flg"]:
                emureg = self.r2api.getRegValue(register["name"])
                try:
                    reg_value = solver.simplify(state.registers[regname])
                    if reg_value.as_long() != emureg:
                        print("%s: %s , %s" % (register["name"], reg_value, emureg))
                except Exception as e:
                    #print(e)
                    pass