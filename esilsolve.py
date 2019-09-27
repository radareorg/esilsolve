from r2api import R2API
import solver
import esilops
import json
from esilclasses import * 
from esilregister import *
import re

import logging

class ESILWord:
    def __init__(self, word=None, context=None):
        self.word = word

        if context != None:
            self.context = context
            self.bits = context["info"]["bits"]

            self.registers = self.context["registers"]
            self.memory = self.context["memory"]
    
    def isConditional(self):
        return (self.word[0] == "?")

    def isOperator(self):
        return (self.word in esilops.opcodes)

    def isLiteral(self):
        return (self.word.isdigit() or self.word[:2] == "0x")

    def isRegister(self):
        return (self.word in self.registers)

    def getRegister(self):
        register = self.registers[self.word]
        return register

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
        op(self.word, stack, self.context)

class ESILSolver:
    def __init__(self, r2api=None):
        self.solver = solver.Solver()
        self.stack = []
        self.model = None

        self.conditionals = {}
        self.cond_count = 0

        if r2api == None:
            r2api = R2API()

        self.r2api = r2api
        self.info = self.r2api.getInfo()
        self.context = {
            "registers": {}, 
            "aliases": {}, 
            "memory": {}, 
            "info": self.info["info"]
        }

        if "info" in self.info:
            self.bits = self.info["info"]["bits"]
        else:
            self.bits = 64

        # get information about the registers
        self.initRegisters()
    
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
        self.context["registers"] = self.registers
        self.context["aliases"] = self.aliases

    def setSymbolicRegister(self, name):
        size = self.registers[name].size()
        self.registers[name] = newRegister(name, size)

    def constrainRegister(self, name, val):
        reg = self.registers[name]
        self.solver.add(reg == val)

    def evaluateRegister(self, name):
        val = self.registers[name]

        if self.model == None:
            sat = self.solver.check()
            
            if sat:
                self.model = self.solver.model()
            else:
                raise ESILUnsatException

        return self.model.eval(val)

    def initMemory(self):
        raise esilops.ESILUnimplementedException

    def parseExpression(self, expression):
        if "?" in expression:
            expression = self.parseConditionals(expression)
            
        words = expression.split(",")

        for word_str in words:
            word = ESILWord(word_str, self.context)

            if word.isConditional():
                self.doConditional(word)

            elif word.isOperator():
                word.doOp(self.stack)

            else:
                self.stack.append(word.getPushValue())

    def parseConditionals(self, expression):
        conditionals = re.findall(r"\?\{(.*?)\}", expression)

        for cond in conditionals:
            ident = "?[%d]" % self.cond_count
            self.conditionals[ident] = cond
            self.cond_count += 1

            expression = expression.replace("?{%s}" % cond, ident, 1)

        return expression
        
    def doConditional(self, word):
        if self.popAndEval():
            self.parseExpression(self.conditionals[word.word])

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

if __name__ == "__main__": 

    esilsolver = ESILSolver()
    esilsolver.setSymbolicRegister("rax")
    esilsolver.parseExpression("1,rax,+,rbx,=,1,?{1,rbx,+=},2,bx,+,rbx,=,$$")
    esilsolver.constrainRegister("rbx", 277)

    print(esilsolver.stack)
    print(esilsolver.evaluateRegister("ah"))
    print(esilsolver.evaluateRegister("rax")) 
