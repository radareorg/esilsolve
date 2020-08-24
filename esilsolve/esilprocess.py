import z3
from .r2api import R2API
from . import esilops
from .esilclasses import * 
from .esilstate import *

# some constants for exec type idk
UNCON = 0
IF = 1 
ELSE = 2
EXEC = 3
NO_EXEC = 4

class ESILProcess:
    """ 
    Executes ESIL expressions and handles results

    >>> state.proc.parse_expression("4,rax,rbx,=", state)
    """

    def __init__(self, r2p: R2API = None, **kwargs):
        self.kwargs = kwargs
        self.debug = kwargs.get("debug", False)
        self.trace = kwargs.get("trace", False)
        self._expr_cache = {}

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
        self.lazy = kwargs.get("lazy", False) 

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
    
    def execute_instruction(self, state, instr: Dict):
        offset = instr["offset"]

        if self.debug:
            print("\nexpr: %s" % instr["esil"])
            print("%016x: %s" % (offset, instr["opcode"]))

        # old pc should never be anything other than a BitVecVal  
        #old_pc = state.registers["PC"].as_long() + instr["size"]
        old_pc = offset + instr["size"]

        state.registers["PC"] = old_pc

        if offset in self._expr_cache:
            esil = self._expr_cache[offset]
        else:
            esil = instr["esil"]
            if esil == "" and instr["type"] != "nop":
                if self.vexit != None:
                    try:
                        print("taking vexit for %s" % str(instr))
                        esil = self.vexit.convert(instr)
                    except:
                        pass

            self._expr_cache[offset] = esil.split(",")

        self.parse_expression(esil, state)
        state.steps += 1
        states = []

        pc = state.registers["PC"]
        if z3.is_bv_value(pc):
            new_pc = pc.as_long()

            #if state.target != None:
            #    state.distance = min(state.distance, abs(state.target-new_pc))

            if self.trace:
                self.r2api.emustep()
                self.trace_registers(state)

            states.append(state)
        else:
            # symbolic pc value
            if self.debug:
                print("symbolic pc: %s" % str(pc))

            possible_pcs = []

            # if lazy don't eval, just try both If addresses
            if self.lazy and pc.decl().name() == "if":
                arg1 = z3.simplify(pc.arg(1))
                arg2 = z3.simplify(pc.arg(2))

                if z3.is_bv_value(arg1) and z3.is_bv_value(arg2):
                    possible_pcs = [arg1.as_long(), arg2.as_long()]
            
            if possible_pcs == []:
                possible_pcs = state.eval_max(pc)

            do_clone = len(possible_pcs) > 1

            for possible_pc in possible_pcs:

                # this is the secret to speed, dont always clone states
                if do_clone:
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

        if type(expression) == str:
            words = expression.split(",")
        else:
            words = expression

        word_ind = 0

        goto = None
        goto_condition = None
        goto_depth = 0
        
        while word_ind < len(words):
            #print(words[word_ind], temp_stack1, state.stack)
            word = words[word_ind]
            word_ind += 1

            if word == "?{":
                state.condition = self.do_if(state)

                if type(state.condition) == bool:
                    if state.condition == True:
                        exec_type = EXEC
                    else:
                        exec_type = NO_EXEC

                    state.condition = None
                else:
                    exec_type = IF
                    temp_stack1 = state.stack
                    state.stack = temp_stack1[:]

            elif word == "}{":
                if exec_type == NO_EXEC:
                    exec_type = EXEC
                elif exec_type == EXEC:
                    exec_type = NO_EXEC
                else:
                    state.condition = z3.Not(state.condition)
                    exec_type = ELSE
                    temp_stack2 = state.stack
                    state.stack = temp_stack1[:]
                
            elif word == "}":
                if NO_EXEC != exec_type != EXEC:
                    new_stack = []
                    new_temp = temp_stack1
                    if exec_type == ELSE:
                        new_temp = temp_stack2

                    while state.stack != [] and new_temp != []:
                        else_val, = esilops.pop_values(new_temp, state)
                        if_val, = esilops.pop_values(state.stack, state)
                        condval = z3.If(state.condition, if_val, else_val)
                        new_stack.append(z3.simplify(condval))

                    state.condition = None
                    new_stack.reverse()
                    state.stack = new_stack

                exec_type = UNCON

                if goto != None and exec_type != NO_EXEC:
                    word_ind = goto
                    state.condition = goto_condition
                    goto = None

            elif word == "GOTO" and exec_type != NO_EXEC:
                # goto makes things a bit wild
                goto, = esilops.pop_values(state.stack, state)

                if state.condition != None:
                    #print(state.condition)
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

            elif exec_type != NO_EXEC:

                #if word in state.registers:
                #    state.stack.append(word)

                if word in esilops.opcodes:
                    op = esilops.opcodes[word]
                    op(word, state.stack, state)

                else:
                    val = self.get_push_value(word)
                    state.stack.append(val)

    def get_push_value(self, word):
        if(word.isdigit()):
            return int(word)
        elif word[:2] == "0x" or word[:3] == "-0x":
            return int(word, 16)
        elif word[:1] == "-" and word[1:].isdigit():
            return int(word)
        else:
            return word

    def do_if(self, state):
        val, = esilops.pop_values(state.stack, state)
        val = z3.simplify(val)

        if self.debug:
            print("condition val: %s" % val)

        zero = 0
        if z3.is_bv_value(val):
            return val.as_long() != zero
                
        elif z3.is_bv(val):
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