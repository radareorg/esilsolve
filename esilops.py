from esilclasses import *
from esilregisters import *
import solver

SIZE = 64
ONE = solver.BitVecVal(1, SIZE)
ZERO = solver.BitVecVal(0, SIZE)

def pop_value(stack, state):
    val = stack.pop()
    return get_value(val, state)

def get_value(val, state):
    if type(val) == str:
        register = state.registers[val]
        return prepare(register)
    else:
        #state.esil["lastsz"] = SIZE
        return prepare(val)

def prepare(val):
    if solver.is_bv(val):
        #print(val)
        szdiff = SIZE-val.size()
        #print(szdiff, val.size())
        if szdiff > 0:
            return solver.ZeroExt(szdiff, val)
        else:
            return val
    elif solver.is_int(val):
        return solver.Int2BV(val, SIZE)
    else:
        return solver.BitVecVal(val, SIZE)

def pop_int_value(stack, state):
    val = get_value(stack.pop(), state)
    
    if solver.is_bv(val):
        return solver.BV2Int(val)
    else:
        return val

def pop_ext_value(stack, state):
    val = get_value(stack.pop(), state)
    
    if solver.is_bv(val):
        tmp = solver.Concat(solver.BitVecVal(0, val.size()), val)
        return tmp
    else:
        return val

def do_TRAP(op, stack, state):
    raise ESILTrapException

def do_BREAK(op, stack, state):
    raise ESILBreakException

def do_TODO(op, stack, state):
    raise ESILTodoException

def do_SYS(op, stack, state):
    raise ESILUnimplementedException

def do_PCADDR(op, stack, state):
    stack.append(state.registers["PC"])

def do_CMP(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1-arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LT(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1<arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LTE(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1<=arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GT(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1>arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GTE(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1>=arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LS(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1<<arg2)

def do_RS(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1>>arg2)

def do_LRS(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(solver.LShR(arg1, arg2))

def do_LR(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(solver.RotateLeft(arg1, arg2))

def do_RR(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(solver.RotateRight(arg1, arg2))

def do_AND(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1&arg2)

def do_OR(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1|arg2)

def do_XOR(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1^arg2)

def do_ADD(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1+arg2)

def do_SUB(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1-arg2)

def do_MUL(op, stack, state):

    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(arg1*arg2)

def do_DIV(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(solver.If(arg1 == 0, 0, arg1/arg2))

def do_MOD(op, stack, state):
    arg1 = pop_value(stack, state)
    arg2 = pop_value(stack, state)

    stack.append(solver.URem(arg1, arg2))

def do_NOT(op, stack, state):
    arg1 = pop_value(stack, state)
    #print(~arg1)
    stack.append(solver.If(arg1 == 0, ONE, ZERO))

def do_INC(op, stack, state):
    arg1 = pop_value(stack, state)
    stack.append(arg1+1)

def do_DEC(op, stack, state):
    arg1 = pop_value(stack, state)
    stack.append(arg1-1)

def do_EQU(op, stack, state):
    reg = stack.pop()
    val = pop_value(stack, state)
    tmp = get_value(reg, state)

    if state.condition != None:
        val = solver.If(state.condition, val, tmp)

    #setRegisterValue(reg, val, state)
    state.registers[reg] = val
    #print(reg, val)
    state.esil["old"] = tmp
    state.esil["cur"] = val

    state.esil["lastsz"] = state.registers[reg].size()


def do_WEQ(op, stack, state):
    reg = stack.pop()
    val = pop_value(stack, state)
    tmp = prepare(state.registers[reg])

    if state.condition != None:
        val = solver.If(state.condition, val, tmp)

    #setRegisterValue(reg, val, state)
    state.registers.weak_set(reg, val)

def do_OPEQ(op, stack, state):
    reg = stack.pop()
    regval = state.registers[reg]
    newop = op.split("=")[0]
    #val = pop_value(stack, state)

    stack.append(regval)
    opcodes[newop](newop, stack, state)

    stack.append(reg)
    do_EQU(op, stack, state)

def do_SWAP(op, stack, state):
    reg1 = stack.pop()
    reg2 = stack.pop()

    tmp = state.registers[reg1]
    state.registers[reg1] = state.registers[reg2]
    state.registers[reg2] = tmp

def do_PICK(op, stack, state):
    raise ESILUnimplementedException

def do_RPICK(op, stack, state):
    raise ESILUnimplementedException

def do_DUP(op, stack, state):
    stack.append(stack[-1])

# idk if this is relevant to how we are doing things?
def do_NUM(op, stack, state):
    #raise ESILUnimplementedException
    pass

def do_CLEAR(op, stack, state):
    stack.clear()

def do_GOTO(op, stack, state):
    raise ESILUnimplementedException

def memlen(op):
    b1 = op.index("[")
    b2 = op.index("]")
    if op[b1+1:b2].isdigit():
        return int(op[b1+1:b2])

def do_POKE(op, stack, state):
    length = memlen(op)
    addr = pop_value(stack, state)
    data = pop_value(stack, state)

    if state.condition != None:
        tmp = state.memory.read_bv(addr, length)
        data = solver.If(state.condition, data, tmp)

    state.memory.write_bv(addr, data, length)
    state.esil["old"] = addr
    state.esil["lastsz"] = length*8


def do_PEEK(op, stack, state):
    length = memlen(op)
    addr = pop_value(stack, state)

    data = state.memory.read_bv(addr, length)
    stack.append(data)
    state.esil["old"] = addr
    state.esil["cur"] = stack[-1]
    state.esil["lastsz"] = length*8

def do_OPPOKE(op, stack, state):
    length = memlen(op)
    addr = pop_value(stack, state)
    stack.append(addr)

    do_PEEK(op, stack, state)
    newop = op.split("=")[0]
    opcodes[newop](newop, stack, state)
    data = pop_value(stack, state)

    if state.condition != None:
        tmp = state.memory.read_bv(addr, length)
        data = solver.If(state.condition, data, tmp)

    state.memory.write_bv(addr, data, length)
    state.esil["old"] = addr

def do_NOMBRE(op, stack, state):
    raise ESILUnimplementedException

def do_NOP(op, stack, state):
    pass

def genmask(bits):
    
    if type(bits) != int:
        bits = solver.simplify(bits)
        if solver.is_bv(bits):
            bits = bits.as_long()

    m = (2 << 63) - 1
    if(bits > 0 and bits < 64):
        m = (2 << bits) - 1
    
    return m

def lastsz(state):
    try:
        return state.esil["lastsz"]
    except:
        #print(state.info)
        return state.info["info"]["bits"]

# flag op functions
# jesus h g wells christ these are gross
def do_ZF(op, stack, state):
    eq = ((state.esil["cur"] & genmask(lastsz(state)-1)) == ZERO) # 
    stack.append(solver.If(eq, ONE, ZERO))
    
def do_CF(op, stack, state):
    bits = pop_value(stack, state)
    mask = genmask(bits & 0x3f)
    old = state.esil["old"]
    cur = state.esil["cur"]
    cf = solver.ULT((cur & mask), (old & mask))
    stack.append(solver.If(cf, ONE, ZERO))

def do_B(op, stack, state):
    bits = pop_value(stack, state)
    mask = genmask(bits & 0x3f)
    old = state.esil["old"]
    cur = state.esil["cur"]
    bf = solver.ULT((old & mask), (cur & mask))

    #print(bits, mask, solver.simplify(bf))
    stack.append(solver.If(bf, ONE, ZERO))

'''
	// Set if the number of set bits in the least significant _byte_ is a multiple of 2.
	//   - Taken from: https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
	const ut64 c1 = 0x0101010101010101ULL;
	const ut64 c2 = 0x8040201008040201ULL;
	const ut64 c3 = 0x1FF;
	// Take only the least significant byte.
	ut64 lsb = esil->cur & 0xff;
	return r_anal_esil_pushnum (esil, !((((lsb * c1) & c2) % c3) & 1));
'''
def do_P(op, stack, state):
    c1 = solver.BitVecVal(0x0101010101010101, SIZE)
    c2 = solver.BitVecVal(0x8040201008040201, SIZE)
    c3 = solver.BitVecVal(0x1FF, SIZE)

    cur = state.esil["cur"]

    if type(cur) == int:
        cur = solver.BitVecVal(cur, SIZE)
        sz = SIZE
    else:
        sz = cur.size()
        if sz < SIZE:
            cur = solver.ZeroExt(SIZE-sz, cur)

    lsb = cur & solver.BitVecVal(0xff, SIZE)
    #pf = (((((lsb * c1) & c2) % c3) & ONE) != 1)
    pf = ((solver.URem(((lsb * c1) & c2), c3) & ONE) != ONE)
    stack.append(solver.If(pf, ONE, ZERO))

def do_O(op, stack, state):
    bit = pop_value(stack, state)
    old = state.esil["old"]
    cur = state.esil["cur"]
    m = [genmask (bit & 0x3f), genmask ((bit + 0x3f) & 0x3f)]
    c_in = solver.If(solver.ULT((cur & m[0]), (old & m[0])), ONE, ZERO)
    c_out = solver.If(solver.ULT((cur & m[1]), (old & m[1])), ONE, ZERO)
    #print(solver.simplify(c_in))
    #print(solver.simplify(c_out))
    of = ((c_in ^ c_out) == 1)

    stack.append(solver.If(of, ONE, ZERO))

def do_SO(op, stack, state):
    bit = pop_value(stack, state)
    old = state.esil["old"]
    cur = state.esil["cur"]
    m = [genmask (bit & 0x3f), genmask ((bit + 0x3f) & 0x3f)]
    c_0 = solver.If(((old-cur) & m[0]) == (1<<bit), ONE, ZERO)
    c_in = solver.If(solver.ULT((cur & m[0]), (old & m[0])), ONE, ZERO)
    c_out = solver.If(solver.ULT((cur & m[1]), (old & m[1])), ONE, ZERO)
    #print(solver.simplify(c_in))
    #print(solver.simplify(c_out))
    of = ((c_0 ^ c_in) ^ c_out == 1)

    stack.append(solver.If(of, ONE, ZERO))

def do_DS(op, stack, state):
    ds = ((state.esil["cur"] >> (lastsz(state) - 1)) & ONE) == ONE
    stack.append(solver.If(ds, ONE, ZERO))

def do_S(op, stack, state):
    size = pop_value(stack, state)
    s = ((state.esil["cur"] >> size) & ONE) == ONE
    stack.append(solver.If(s, ONE, ZERO))

# jump target??
def do_JT(op, stack, state):
    raise ESILUnimplementedException

def do_JS(op, stack, state):
    raise ESILUnimplementedException

# da fuq
def do_R(op, stack, state):
    stack.append(state.info["bits"] >> 3)

opcodes = {
    "TRAP": do_TRAP,
    "$": do_SYS,
    "$$": do_PCADDR,
    "==": do_CMP,
    "<": do_LT,
    "<=": do_LTE,
    ">": do_GT,
    ">=": do_GTE,
    "<<": do_LS,
    ">>": do_LRS,
    ">>>>": do_RS,
    "<<<": do_LR,
    ">>>": do_RR,
    "&": do_AND,
    "|": do_OR,
    "^": do_XOR,
    "+": do_ADD,
    "-": do_SUB,
    "*": do_MUL,
    "/": do_DIV,
    "%": do_MOD,
    "!": do_NOT,
    "++": do_INC,
    "--": do_DEC,
    "=": do_EQU,
    ":=": do_WEQ,
    "SWAP": do_SWAP,
    "PICK": do_PICK,
    "RPICK": do_RPICK,
    "DUP": do_DUP,
    "NUM": do_NUM,
    "CLEAR": do_CLEAR,
    "BREAK": do_BREAK,
    "GOTO": do_GOTO,
    "TODO": do_TODO,
    "": do_NOP,

    # flag ops
    "$z": do_ZF,
    "$c": do_CF,
    "$b": do_B,
    "$p": do_P,
    "$o": do_O,
    "$so": do_SO,
    "$s": do_S,
    "$ds": do_DS,
    "$jt": do_JT,
    "$js": do_JS,
    "$r": do_R,
}

byte_vals = ["", "*", "1", "2", "4", "8"]
op_vals = ["+", "-", "++", "--", "*", "/", "<<", ">>", "|", "&", "^", "%", "!", ">>>>", ">>>", "<<<"]

for op_val in op_vals:
    opcodes["%s=" % op_val] = do_OPEQ

for byte_val in byte_vals:
    opcodes["=[%s]" % byte_val] = do_POKE

    for op_val in op_vals:
        opcodes["%s=[%s]" % (op_val, byte_val)] = do_OPPOKE

for byte_val in byte_vals:
    opcodes["[%s]" % byte_val] = do_PEEK

