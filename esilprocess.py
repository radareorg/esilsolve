from r2api import R2API
import solver
import esilops
import json
from esilclasses import * 
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
    
    def is_if(self):
        return (self.word == "?{")

    def is_else(self):
        return (self.word == "}{")

    def is_end_if(self):
        return (self.word == "}")

    def is_operator(self):
        return (self.word in esilops.opcodes)

    def is_literal(self):
        if (self.word.isdigit() or (self.len > 2 and self.word[:2] == "0x")):
            return True
        elif self.len > 1 and self.word[0] == "-" and self.word[1:].isdigit():
            return True
        else: 
            return False

    def is_register(self):
        return (self.word in self.registers)

    def get_register(self):
        #register = self.registers[self.word]
        return self.word

    def get_literal_value(self):
        if(self.word.isdigit()):
            return int(self.word)
        elif self.len > 2 and self.word[:2] == "0x":
            return int(self.word, 16)
        elif self.len > 1 and self.word[0] == "-" and self.word[1:].isdigit():
            return int(self.word)

    def get_push_value(self):
        if(self.is_literal()):
            val = self.get_literal_value()
            return val

        elif(self.is_register()):
            return self.get_register()

        else:
            raise esilops.ESILUnimplementedException

    def do_op(self, stack):
        op = esilops.opcodes[self.word]
        op(self.word, stack, self.state)

# some constants for exec type idk
UNCON = 0
IF = 1 
ELSE = 2

class ESILProcess:
    def __init__(self, r2p=None, debug=False, trace=False):
        self.debug = debug
        self.trace = trace

        self.conditionals = {}
        self.cond_count = 0

        if r2p == None:
            r2api = R2API()
        else:
            r2api = r2p

        self.r2api = r2api
        self.info = self.r2api.get_info()
    
    def execute_instruction(self, state, instr):
        if self.debug:
            print("\nexpr: %s" % instr["esil"])
            print("%016x: %s" % (instr["offset"], instr["opcode"]))

        # clone the original state if theres a peek
        # this is so terrible 
        og_state = None
        if "[" in instr["esil"] and state.memory.multi_concretize:
            og_state = state.clone()

        # old pc should never be anything other than a BitVecVal        
        old_pc = state.registers["PC"].as_long() 
        self.parse_expression(instr["esil"], state)
        state.steps += 1
        states = []

        # christ this is getting convoluted
        if state.memory.hit_symbolic_addr and og_state != None: 
            state.memory.hit_symbolic_addr = False
            
            for addr in state.memory.concrete_addrs:
                for val in addr["values"]:
                    new_state = og_state.clone()
                    new_state.solver.add(addr["bv"] == val)

                    states.extend(self.execute_instruction(new_state, instr))

            state.memory.concrete_addrs = []

        pc = state.registers["PC"]
        if solver.is_bv_value(pc):
            new_pc = pc.as_long()

            if new_pc == old_pc:
                state.registers["PC"] = old_pc + instr["size"]

            if self.trace:
                self.r2api.emustep()
                self.trace_registers(state)

            states.append(state)
        else:
            # symbolic pc value
            if self.debug:
                print("symbolic pc: %s" % str(pc))

            possible_pcs = solver.EvalMax(state.solver, pc)

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

                states.append(new_state)

        return states

    def parse_expression(self, expression, state):

        temp_stack1 = None
        temp_stack2 = None
        exec_type = UNCON
        expression = expression.replace("|=}", "|=,}") # typo fix
        words = expression.split(",")

        for word_str in words:
            word = ESILWord(word_str, state)

            if word.is_if():
                state.condition = self.do_if(word, state)
                exec_type = IF
                temp_stack1 = state.stack
                state.stack = []

            elif word.is_else():
                state.condition = solver.Not(state.condition)
                exec_type = ELSE
                temp_stack2 = state.stack
                state.stack = []
                
            elif word.is_end_if():
                # this code is weird and i dont like it
                # but its just necessary to do in some way
                if exec_type == ELSE:
                    state.stack.reverse()
                    temp_stack2.reverse()

                    while len(state.stack) > 0:
                        if_val = esilops.pop_value(temp_stack2, state)
                        else_val = esilops.pop_value(state.stack, state)
                        #print(if_val, else_val)
                        condval = solver.If(state.condition, else_val, if_val)
                        temp_stack1.append(solver.simplify(condval))
                        #temp_stack1.append(condval)
                else:
                    temp_stack1 += state.stack

                state.condition = None
                exec_type = UNCON
                state.stack = temp_stack1

            else:
                if word.is_operator():
                    word.do_op(state.stack)
                else:
                    val = word.get_push_value()
                    state.stack.append(val)

        
    def do_if(self, word, state):
        val = esilops.pop_value(state.stack, state)
        if self.debug:
            print("condition val: %s" % val)

        zero = 0
        if solver.is_bv(val):
            zero = solver.BitVecVal(0, val.size())

        return val != zero

    def trace_registers(self, state):
        for regname in state.registers._registers:
            register = state.registers._registers[regname]
            #print(regname, reg_value)
            if register["type_str"] in ["gpr", "flg"]:
                emureg = self.r2api.get_reg_value(register["name"])
                try:
                    reg_value = solver.simplify(state.registers[regname])
                    #print(reg_value)
                    #if reg_value.as_long() != emureg:
                    print("%s: %s , %s" % (register["name"], reg_value, emureg))
                except Exception as e:
                    #print(e)
                    pass

    def clone(self):
        clone = self.__class__(self.r2api, debug=self.debug, trace=self.trace)
        return clone