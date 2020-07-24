import z3
from .r2api import R2API
from . import esilops
from .esilclasses import * 
from .esilstate import *

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

        # this depth limit is maybe already too high
        # condition "size" scales like 2**limit
        self.goto_depth_limit = 16

        # try to init vexit, an optional module that uses vex
        # if an esil expression is not available
        # its not pretty but it (sort of) works (sometimes)
        try:
            from .vexit import VexIt
            self.vexit = VexIt(
                self.info["info"]["arch"], 
                self.info["info"]["bits"])
        except:
            self.vexit = None
    
    def execute_instruction(self, state, instr):
        if self.debug:
            print("\nexpr: %s" % instr["esil"])
            print("%016x: %s" % (instr["offset"], instr["opcode"]))

        # clone the original state if theres a peek
        #og_state = None
        #if instr["refptr"] and state.memory.multi_concretize:
        #    og_state = state.clone()

        # old pc should never be anything other than a BitVecVal        
        old_pc = state.registers["PC"].as_long() + instr["size"]
        state.registers["PC"] = old_pc

        esil = instr["esil"]
        if esil == "" and instr["type"] != "nop":
            if self.vexit != None:
                try:
                    print("taking vexit for %s" % str(instr))
                    esil = self.vexit.convert(instr)
                except:
                    pass

        self.parse_expression(esil, state)
        state.steps += 1
        states = []

        # christ this is getting convoluted
        '''if state.memory.hit_symbolic_addr and og_state != None: 
            state.memory.hit_symbolic_addr = False
            
            for addr in state.memory.concrete_addrs:
                for val in addr["values"]:
                    new_state = og_state.clone()
                    new_state.constrain(addr["bv"] == val)

                    states.extend(self.execute_instruction(new_state, instr))

            state.memory.concrete_addrs = []'''

        pc = state.registers["PC"]
        if z3.is_bv_value(pc):
            new_pc = pc.as_long()

            if state.target != None:
                state.distance = min(state.distance, abs(state.target-new_pc))

            if self.trace:
                self.r2api.emustep()
                self.trace_registers(state)

            states.append(state)
        else:
            # symbolic pc value
            if self.debug:
                print("symbolic pc: %s" % str(pc))

            possible_pcs = state.eval_max(pc)
            pc_count = len(possible_pcs)

            for possible_pc in possible_pcs:

                # this is the secret to speed, dont always clone states
                if pc_count > 1:
                    new_state = state.clone()
                else:
                    new_state = state

                new_state.constrain(pc == possible_pc)
                new_state.registers["PC"] = possible_pc

                states.append(new_state)

        return states

    def parse_expression(self, expression, state):

        temp_stack1 = []
        temp_stack2 = []
        exec_type = UNCON
        #expression = expression.replace("|=}", "|=,}") # typo fix
        words = expression.split(",")
        word_ind = 0

        # ahhhhh 
        goto = None
        goto_condition = None
        goto_depth = 0
        
        while word_ind < len(words):
            #print(words[word_ind], temp_stack1, state.stack)
            word = words[word_ind]
            word_ind += 1

            if word == "?{":
                state.condition = self.do_if(state)
                exec_type = IF
                temp_stack1 = state.stack
                state.stack = temp_stack1[:]

            elif word == "}{":
                state.condition = z3.Not(state.condition)
                exec_type = ELSE
                temp_stack2 = state.stack
                state.stack = temp_stack1[:]
                
            elif word == "}":
                new_stack = []
                new_temp = temp_stack1
                if exec_type == ELSE:
                    new_temp = temp_stack2

                while len(state.stack) > 0 and len(new_temp) > 0:
                    else_val, = esilops.pop_values(new_temp, state)
                    if_val, = esilops.pop_values(state.stack, state)
                    condval = z3.If(state.condition, if_val, else_val)
                    new_stack.append(z3.simplify(condval))

                state.condition = None
                exec_type = UNCON
                new_stack.reverse()
                state.stack = new_stack

                if goto != None:
                    word_ind = goto
                    state.condition = goto_condition
                    goto = None

            elif word == "GOTO":
                # goto makes things a bit wild
                goto, = esilops.pop_values(state.stack, state)
                goto_depth += 1

                if z3.is_bv_value(goto):
                    goto = goto.as_long()

                if goto_depth > self.goto_depth_limit:
                    # constrain the current condition to not be true
                    # effectively cutting off the nested gotos
                    state.constrain(z3.Not(state.condition))
                    goto = None
            
                elif self.check_condition(state.condition, state):
                    goto_condition = state.condition

                    # there should be nothing between GOTO and else/endif
                    # but we will enforce this anyway
                    word_str = words[word_ind]
                    while word_str not in ("}", "}{"):
                        word_ind += 1
                        word_str = words[word_ind]
                    
                else:
                    goto = None

            else:
                if word in esilops.opcodes:
                    op = esilops.opcodes[word]
                    op(word, state.stack, state)

                else:
                    val = get_push_value(word)
                    state.stack.append(val)

    def do_if(self, state):
        val, = esilops.pop_values(state.stack, state)
        if self.debug:
            print("condition val: %s" % val)

        zero = 0
        if z3.is_bv(val):
            zero = z3.BitVecVal(0, val.size())

        if state.condition == None:
            return z3.simplify(val != zero)
        else:
            return z3.simplify(z3.And(val != zero, state.condition))

    def check_condition(self, condition, state):
        if condition == None:
            return True

        state.solver.push()
        state.solver.add(condition)
        is_sat = state.is_sat()
        state.solver.pop()

        return is_sat

    def trace_registers(self, state):
        for regname in state.registers._registers:
            register = state.registers._registers[regname]
            #print(regname, reg_value)
            if register["type_str"] in ("gpr", "flg"):
                emureg = self.r2api.get_reg_value(register["name"])
                try:
                    reg_value = z3.simplify(state.registers[regname])
                    #print(reg_value)
                    if reg_value.as_long() != emureg:
                        print("%s: %s , %s" % (register["name"], reg_value, emureg))
                except Exception as e:
                    #print(e)
                    pass

    def clone(self):
        clone = self.__class__(self.r2api, debug=self.debug, trace=self.trace)
        return clone


def get_literal_value(word):
    if(word.isdigit()):
        return int(word)
    elif word.startswith("0x"):
        return int(word, 16)
    elif word.startswith("-") and word[1:].isdigit():
        return int(word)

def get_push_value(word):
    literal = get_literal_value(word)
    if literal != None:
        return literal

    else:
        return word