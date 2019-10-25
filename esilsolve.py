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

        if state != None:
            self.state = state
            self.bits = state.info["info"]["bits"]

            self.registers = state.registers
            self.memory = state.memory
    
    def isConditional(self):
        return (self.word[0] == "?")

    def isOperator(self):
        return (self.word in esilops.opcodes)

    def isLiteral(self):
        return (self.word.isdigit() or self.word[:2] == "0x")

    def isRegister(self):
        return (self.word in self.registers)

    def getRegister(self):
        #register = self.registers[self.word]
        return self.word

    def getLiteralValue(self):
        if(self.word.isdigit()):
            return int(self.word)
        elif self.word[:2] == "0x":
            return int(self.word, 16)

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
    def __init__(self, r2p=None, init=True, debug=False, trace=False):
        self.debug = debug
        self.trace = trace
        self.states = []

        self.conditionals = {}
        self.cond_count = 0

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

    def run(self, state, target=None):
        # if target is None exec until ret
        if target == None:
            find = lambda x, s: x["opcode"] == "ret"
        elif type(target) == int:
            find = lambda x, s: x["offset"] == target

        found = False

        while not found:
            instr = self.r2api.disass()[0]
            found = find(instr, state)

            if not found:
                self.executeInstruction(state, instr)
    
    def executeInstruction(self, state, instr):
        if self.debug:
            print("expr: %s" % instr["esil"])
            print("opcode: %s" % instr["opcode"])

        # pc should never be anything other than a BitVecVal
        old_pc = state.registers["PC"].as_long() 
        self.parseExpression(instr["esil"], state)
        new_pc = state.registers["PC"].as_long()

        if new_pc == old_pc:
            self.r2api.step(instr["size"])
            # this may be wrong for arm
            state.registers["PC"] = old_pc + instr["size"]
        else:
            self.r2api.seek(new_pc)

        if self.trace:
            #print(state.registers.getValues())
            self.r2api.emustep()
            #print(self.r2api.getAllRegisters())
            self.traceRegisters(state)

    def initState(self):
        if len(self.states) > 0:
            return self.states[0]

        state = ESILState(self.r2api)
        self.states.append(state)
        return state

    def parseExpression(self, expression, state):

        stack = state.stack

        if "?" in expression:
            expression = self.parseConditionals(expression)
            
        words = expression.split(",")

        for word_str in words:
            if word_str == "": continue

            word = ESILWord(word_str, state)

            if word.isConditional():
                self.doConditional(word, state)

            elif word.isOperator():
                word.doOp(stack)

            else:
                stack.append(word.getPushValue())

    def parseConditionals(self, expression):
        conditionals = re.findall(r"\?\{,(.*?),\}", expression)

        for cond in conditionals:
            ident = "?[%d]" % self.cond_count
            self.conditionals[ident] = cond
            self.cond_count += 1

            expression = expression.replace("?{,%s,}" % cond, ident, 1)

        return expression
        
    # TODO: change this logic
    def doConditional(self, word, state):
        val = state.stack.pop()
        return

        expr = self.conditionals.pop(word.word)

        # uhhh this sucks
        if expr == "1,cf,:=":
            return

        for option in [0, 1]:
            state.solver.push()
            cond = val == option
            state.solver.add(cond)
            sat = state.solver.check()
            print(sat)
            if str(sat) == "sat" and option == 1:
                #print("Using conditional: %s" % str(cond))
                self.parseExpression(expr, state)
                break
            elif str(sat) == "sat":
                break

            state.solver.pop()

    def traceRegisters(self, state):
        for regname in state.registers._registers:
            register = state.registers._registers[regname]
            if register["parent"] == None and register["type_str"] in ["gpr", "flg"]:
                emureg = self.r2api.getRegValue(register["name"])
                print("%s: %s , %s" % (register["name"], register["bv"], emureg))