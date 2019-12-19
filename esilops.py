from esilclasses import *
from esilregisters import *
import solver

SIZE = 64
ONE = solver.BitVecVal(1, SIZE)
ZERO = solver.BitVecVal(0, SIZE)

def popValue(stack, state):
    val = stack.pop()
    return getValue(val, state)

def getValue(val, state):
    if type(val) == str:
        register = state.registers[val]
        state.esil["lastsz"] = register.size()
        return prepare(register)
    else:
        state.esil["lastsz"] = SIZE
        return prepare(val)

def prepare(val):
    if solver.is_bv(val):
        szdiff = SIZE-val.size()
        if szdiff > 0:
            return solver.ZeroExt(szdiff, val)
        else:
            return val
    elif solver.is_int(val):

        return solver.Int2BV(val, SIZE)
    else:
        return solver.BitVecVal(val, SIZE)

def popIntValue(stack, state):
    val = getValue(stack.pop(), state)
    
    if solver.is_bv(val):
        return solver.BV2Int(val)
    else:
        return val

def popExtValue(stack, state):
    val = getValue(stack.pop(), state)
    
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
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1-arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LT(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1<arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LTE(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1<=arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GT(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1>arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GTE(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1>=arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LS(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1<<arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_RS(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1>>arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LRS(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(solver.LShR(arg1, arg2))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LR(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(solver.RotateLeft(arg1, arg2))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_RR(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(solver.RotateRight(arg1, arg2))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_AND(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1&arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_OR(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1|arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_XOR(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1^arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_ADD(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1+arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_SUB(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1-arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_MUL(op, stack, state):

    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1*arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_DIV(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(solver.If(arg1 == 0, 0, arg1/arg2))

    #solver.div
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_MOD(op, stack, state):
    arg1 = popValue(stack, state)
    arg2 = popValue(stack, state)

    stack.append(arg1%arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_NOT(op, stack, state):
    arg1 = popValue(stack, state)
    #print(~arg1)
    stack.append(solver.If(arg1 == 0, ONE, ZERO))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_INC(op, stack, state):
    arg1 = popValue(stack, state)
    stack.append(arg1+1)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_DEC(op, stack, state):
    arg1 = popValue(stack, state)
    stack.append(arg1-1)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_EQU(op, stack, state):
    reg = stack.pop()
    val = popValue(stack, state)
    tmp = prepare(state.registers[reg])

    if state.condition != None:
        val = solver.If(state.condition, val, tmp)

    #setRegisterValue(reg, val, state)
    state.registers[reg] = val
    #print(reg, val)
    state.esil["old"] = tmp
    state.esil["cur"] = val

def do_WEQ(op, stack, state):
    reg = stack.pop()
    val = popValue(stack, state)
    tmp = prepare(state.registers[reg])

    if state.condition != None:
        val = solver.If(state.condition, val, tmp)

    #setRegisterValue(reg, val, state)
    state.registers.weakSet(reg, val)

def do_OPEQ(op, stack, state):
    reg = stack.pop()
    regval = state.registers[reg]
    newop = op.split("=")[0]
    #val = popValue(stack, state)

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
    return int(op[b1+1:b2])

def do_POKE(op, stack, state):
    length = memlen(op)
    addr = popValue(stack, state)
    data = popValue(stack, state)

    if state.condition != None:
        tmp = state.memory.readBV(addr, length)
        data = solver.If(state.condition, data, tmp)

    state.memory.writeBV(addr, data, length)
    state.esil["old"] = addr

def do_PEEK(op, stack, state):
    length = memlen(op)
    addr = popValue(stack, state)

    data = state.memory.readBV(addr, length)
    stack.append(data)
    state.esil["old"] = addr
    state.esil["cur"] = stack[-1]

def do_OPPOKE(op, stack, state):
    length = memlen(op)
    addr = popValue(stack, state)
    stack.append(addr)

    do_PEEK(op, stack, state)
    newop = op.split("=")[0]
    opcodes[newop](newop, stack, state)
    data = popValue(stack, state)

    if state.condition != None:
        tmp = state.memory.readBV(addr, length)
        data = solver.If(state.condition, data, tmp)

    state.memory.writeBV(addr, data, length)
    state.esil["old"] = addr

def do_NOMBRE(op, stack, state):
    raise ESILUnimplementedException

def do_NOP(op, stack, state):
    pass

def genmask(bits):
    bits = solver.simplify(bits)
    if solver.is_bv(bits):
        bits = bits.as_long()

    m = (2 << 63) - 1
    if(bits > 0 and bits < 64):
        m = (2 << bits) - 1
    
    return m

def lastsz(state):
    return state.esil["lastsz"]

    old = state.esil["old"]
    cur = state.esil["cur"]

    try:
        return cur.size()
    except:
        pass
    
    try:
        return old.size()
    except:
        pass
    
    return state.info["bits"]

# flag op functions
# jesus h g wells christ these are gross
def do_ZF(op, stack, state):
    eq = (state.esil["cur"] == 0) # 
    #stack.append(eq)
    stack.append(solver.If(eq, ONE, ZERO))
    
def do_CF(op, stack, state):
    bits = popValue(stack, state)
    mask = genmask(bits & 0x3f)
    #cf = (state.esil["cur"] & mask) < (state.esil["old"] & mask)
    cf = solver.ULT((state.esil["cur"] & mask), (state.esil["old"] & mask))

    stack.append(solver.If(cf, ONE, ZERO))

def do_B(op, stack, state):
    bits = popValue(stack, state)
    mask = genmask((bits + 0x3f) & 0x3f)
    #print(solver.simplify((state.esil["old"] & mask)), solver.simplify((state.esil["cur"] & mask)))
    bf = solver.ULT((state.esil["old"] & mask), (state.esil["cur"] & mask))

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
    pf = (((((lsb * c1) & c2) % c3) & solver.BitVecVal(1, SIZE)) != 1)
    stack.append(solver.If(pf, ONE, ZERO))

def do_O(op, stack, state):
    try:
        old = state.esil["old"]
        cur = state.esil["cur"]
        sz = lastsz(state)
        m = [sz-1, sz-2]
        of = (((cur & m[0]) < (old & m[0])) ^ ((cur & m[1]) < (old & m[1])) == 1)

        stack.append(solver.If(of, ONE, ZERO))
    except:
        stack.append(ZERO)

def do_DS(op, stack, state):
    ds = ((state.esil["cur"] >> (lastsz(state) - 1)) & 1) == 1
    stack.append(solver.If(ds, ONE, ZERO))

def do_S(op, stack, state):
    try:
        size = popValue(stack, state)
        s = ((state.esil["cur"] >> size) & 1) == 1
        stack.append(solver.If(s, ONE, ZERO))
    except:
        stack.append(ZERO)

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

