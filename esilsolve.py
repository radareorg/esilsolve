from r2api import R2API
import solver
import esilops
import json
import arch
from esilclasses import * 
from esilregister import ESILRegisters

class ESILWord:
    def __init__(self, word=None, context=None):
        self.word = word

        if context != None:
            self.context = context
            self.bits = context["info"]["bits"]

            self.registers = self.context["registers"]
            self.memory = self.context["memory"]
    
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

        if r2api == None:
            r2api = R2API()

        self.r2api = r2api
        self.info = self.r2api.getInfo()
        self.context = {"registers": {}, "memory": {}, "info": self.info["info"]}

        if "info" in self.info:
            self.bits = self.info["info"]["bits"]
        else:
            self.bits = 64

        # get information about the registers
        self.initRegisters()
    
    def initRegisters(self):
        self.register_info = self.r2api.getRegisterInfo()
        registers = self.register_info["reg_info"]
        register_values = self.r2api.getAllRegisters()

        for register in registers:
            register["value"] = register_values[register["name"]]

        self.registers = ESILRegisters(registers) #reg_dict
        self.context["registers"] = self.registers

    def setSymbolicRegister(self, name):
        size = self.registers[name].size()
        self.registers[name] = newRegister(name, size)

    def constrainRegister(self, name, val):
        reg = self.registers[name]
        self.solver.add(reg == val)

    def initMemory(self):
        raise esilops.ESILUnimplementedException

    def parseExpression(self, expression):
        words = expression.split(",")

        for word_str in words:
            word = ESILWord(word_str, self.context)

            if word.isOperator():
                word.doOp(self.stack)

            else:
                self.stack.append(word.getPushValue())

    def popAndEval(self):
        val = self.stack.pop()

        if type(val) == int:
            return val
            
        if self.model == None:
            sat = self.solver.check()
            self.model = self.solver.model()

        return self.model.eval(val)

if __name__ == "__main__": 

    esilsolver = ESILSolver()
    esilsolver.setSymbolicRegister("rax")
    esilsolver.parseExpression("1,rax,+,rbx,=,rax")
    esilsolver.constrainRegister("rbx", 3)

    print(esilsolver.stack)
    print(esilsolver.popAndEval()) # solves for rax, gives 2
