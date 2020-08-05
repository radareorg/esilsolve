from .esilclasses import *
import z3

SIZE = 64
ONE = z3.BitVecVal(1, SIZE)
ZERO = z3.BitVecVal(0, SIZE)
NEGONE = z3.BitVecVal(-1, SIZE)

def pop_values(stack, state, num=1, signext=False):
    return [get_value(stack.pop(), state, signext) for i in range(num)]

def get_value(val, state, signext=False):
    if type(val) == str:
        register = state.registers[val]
        return prepare(register, signext)
    else:
        return prepare(val)

def prepare(val, signext=False):
    if z3.is_bv(val):
        #print(val)
        szdiff = SIZE-val.size()
        #print(szdiff, val.size())
        if szdiff > 0:
            if signext:
                return z3.SignExt(szdiff, val)
            else:
                return z3.ZeroExt(szdiff, val)
        else:
            return val
    elif z3.is_int(val):
        return z3.Int2BV(val, SIZE)
    else:
        return z3.BitVecVal(val, SIZE)

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
    arg1, arg2 = pop_values(stack, state, 2)
    #stack.append(arg1-arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = arg1-arg2

def do_LT(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2, signext=True)
    stack.append(z3.If(arg1 < arg2, ONE, ZERO))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LTE(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2, signext=True)
    stack.append(z3.If(arg1 <= arg2, ONE, ZERO))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GT(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2, signext=True)
    stack.append(z3.If(arg1 > arg2, ONE, ZERO))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GTE(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2, signext=True)
    stack.append(z3.If(arg1 >= arg2, ONE, ZERO))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LS(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1<<arg2)

def do_RS(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2, signext=True)
    stack.append(arg1>>arg2)

def do_LRS(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(z3.LShR(arg1, arg2))

def do_LR(op, stack, state):
    #arg1, arg2 = pop_values(stack, state, 2)
    arg1_val = stack.pop()

    size = SIZE
    if z3.is_bv(arg1_val):
        arg1 = arg1_val
        size = arg1.size()
    elif type(arg1_val) == str:
        arg1 =  state.registers[arg1_val]
        size = arg1.size()
    else:
        arg1 = prepare(arg1_val)

    arg2, = pop_values(stack, state, 1)

    if arg2.size() > size:
        arg2 = z3.Extract(size-1, 0, arg2)

    stack.append(z3.RotateLeft(arg1, arg2))

def do_RR(op, stack, state):
    #arg1, arg2 = pop_values(stack, state, 2)
    arg1_val = stack.pop()

    size = SIZE
    if z3.is_bv(arg1_val):
        arg1 = arg1_val
        size = arg1.size()
    elif type(arg1_val) == str:
        arg1 =  state.registers[arg1_val]
        size = arg1.size()
    else:
        arg1 = prepare(arg1_val)

    arg2, = pop_values(stack, state, 1)

    if arg2.size() > size:
        arg2 = z3.Extract(size-1, 0, arg2)

    stack.append(z3.RotateRight(arg1, arg2))

def do_AND(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1&arg2)

def do_OR(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1|arg2)

def do_XOR(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1^arg2)

def do_ADD(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1+arg2)

def do_SUB(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1-arg2)

def do_MUL(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1*arg2)

def do_DIV(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(z3.If(arg2 == ZERO, NEGONE, z3.UDiv(arg1,arg2)))

def do_SDIV(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(z3.If(arg2 == ZERO, NEGONE, arg1/arg2))

def do_SIGN(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    size = arg2
    
    if z3.is_bv(size):
        size = size.as_long()

    if not z3.is_bv(arg1):
        arg1 = z3.BitVecVal(arg1, SIZE)

    stack.append(z3.SignExt(SIZE-size, z3.Extract(size-1, 0, arg1)))

def do_MOD(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(z3.URem(arg1, arg2))

def do_SMOD(op, stack, state):
    arg1, arg2 = pop_values(stack, state, 2)
    stack.append(arg1 % arg2)

def do_NOT(op, stack, state):
    arg1, = pop_values(stack, state)
    stack.append(z3.If(arg1 == ZERO, ONE, ZERO))

def do_INC(op, stack, state):
    arg1, = pop_values(stack, state)
    stack.append(arg1+1)

def do_DEC(op, stack, state):
    arg1, = pop_values(stack, state)
    stack.append(arg1-1)

def do_EQU(op, stack, state):
    reg = stack.pop()
    val, = pop_values(stack, state)
    tmp = get_value(reg, state)

    if state.condition != None:
        val = z3.If(state.condition, val, tmp)

    state.registers[reg] = val
    state.esil["old"] = tmp
    state.esil["cur"] = val

    state.esil["lastsz"] = state.registers[reg].size()

def do_WEQ(op, stack, state):
    reg = stack.pop()
    val, = pop_values(stack, state)
    tmp = prepare(state.registers[reg])

    if state.condition != None:
        val = z3.If(state.condition, val, tmp)

    state.registers.weak_set(reg, val)

def do_OPEQ(op, stack, state):
    reg = stack.pop()
    regval = state.registers[reg]
    newop = op.split("=")[0]

    stack.append(reg)
    opcodes[newop](newop, stack, state)

    stack.append(reg)
    do_EQU(op, stack, state)

def do_SWAP(op, stack, state):
    v1 = stack.pop()
    v2 = stack.pop()
    stack.append(v1)
    stack.append(v2)

# picks will fail for symbolic n
# i hope those dont occur
def do_PICK(op, stack, state):
    n, = pop_values(stack, state)
    if z3.is_bv_value(n):
        n = n.as_long()
    
    stack.append(stack[-1*(n+1)])

def do_RPICK(op, stack, state):
    n, = pop_values(stack, state)
    if z3.is_bv_value(n):
        n = n.as_long()
    
    stack.append(stack[n])

def do_DUP(op, stack, state):
    stack.append(stack[-1])

def do_NUM(op, stack, state):
    val, = pop_values(stack, state)
    stack.append(val)

def do_CLEAR(op, stack, state):
    stack.clear()

def do_GOTO(op, stack, state):
    # this gets implemented in esilprocess
    pass

def memlen(op, state):
    b1 = op.index("[")
    b2 = op.index("]")
    if op[b1+1:b2].isdigit():
        return int(op[b1+1:b2])
    else:
        return int(state.bits/8)

def do_POKE(op, stack, state):
    length = memlen(op, state)
    addr, data = pop_values(stack, state, 2)

    if state.condition != None:
        tmp = state.memory.read_bv(addr, length)
        data = z3.If(state.condition, data, tmp)

    state.memory.write_bv(addr, data, length)
    state.esil["old"] = addr
    state.esil["lastsz"] = length*8

def do_PEEK(op, stack, state):
    length = memlen(op, state)
    addr, = pop_values(stack, state)

    data = state.memory.read_bv(addr, length)
    stack.append(data)
    state.esil["old"] = addr
    state.esil["cur"] = prepare(stack[-1])
    state.esil["lastsz"] = length*8

def do_OPPOKE(op, stack, state):
    length = memlen(op, state)
    addr, = pop_values(stack, state)
    stack.append(addr)

    do_PEEK(op, stack, state)
    newop = op.split("=")[0]
    opcodes[newop](newop, stack, state)
    data, = pop_values(stack, state)

    if state.condition != None:
        tmp = state.memory.read_bv(addr, length)
        data = z3.If(state.condition, data, tmp)

    state.memory.write_bv(addr, data, length)
    state.esil["old"] = addr

def do_NOMBRE(op, stack, state):
    raise ESILUnimplementedException

def do_NOP(op, stack, state):
    pass

def genmask(bits):
    
    if type(bits) != int:
        bits = z3.simplify(bits)
        if z3.is_bv(bits):
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
        return state.bits

# flag op functions
# these are essentially taken from esil.c
def do_ZF(op, stack, state):
    eq = ((state.esil["cur"] & genmask(lastsz(state)-1)) == ZERO) # 
    stack.append(z3.If(eq, ONE, ZERO))
    
def do_CF(op, stack, state):
    bits, = pop_values(stack, state)
    mask = genmask(bits & 0x3f)
    old = state.esil["old"]
    cur = state.esil["cur"]
    cf = z3.ULT((cur & mask), (old & mask))
    stack.append(z3.If(cf, ONE, ZERO))

def do_B(op, stack, state):
    bits, = pop_values(stack, state)
    mask = genmask(bits & 0x3f)
    old = state.esil["old"]
    cur = state.esil["cur"]
    bf = z3.ULT((old & mask), (cur & mask))

    #print(bits, mask, z3.simplify(bf))
    stack.append(z3.If(bf, ONE, ZERO))

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
    c1 = z3.BitVecVal(0x0101010101010101, SIZE)
    c2 = z3.BitVecVal(0x8040201008040201, SIZE)
    c3 = z3.BitVecVal(0x1FF, SIZE)

    cur = prepare(state.esil["cur"])
    lsb = cur & z3.BitVecVal(0xff, SIZE)
    #pf = (((((lsb * c1) & c2) % c3) & ONE) != 1)
    pf = ((z3.URem(((lsb * c1) & c2), c3) & ONE) != ONE)
    stack.append(z3.If(pf, ONE, ZERO))

def do_O(op, stack, state):
    bit, = pop_values(stack, state)
    old = state.esil["old"]
    cur = state.esil["cur"]
    m = [genmask (bit & 0x3f), genmask ((bit + 0x3f) & 0x3f)]
    c_in = z3.If(z3.ULT((cur & m[0]), (old & m[0])), ONE, ZERO)
    c_out = z3.If(z3.ULT((cur & m[1]), (old & m[1])), ONE, ZERO)
    #print(z3.simplify(c_in))
    #print(z3.simplify(c_out))
    of = ((c_in ^ c_out) == 1)

    stack.append(z3.If(of, ONE, ZERO))

def do_SO(op, stack, state):
    bit, = pop_values(stack, state)
    old = state.esil["old"]
    cur = state.esil["cur"]
    m = [genmask (bit & 0x3f), genmask ((bit + 0x3f) & 0x3f)]
    c_0 = z3.If(((old-cur) & m[0]) == (1<<bit), ONE, ZERO)
    c_in = z3.If(z3.ULT((cur & m[0]), (old & m[0])), ONE, ZERO)
    c_out = z3.If(z3.ULT((cur & m[1]), (old & m[1])), ONE, ZERO)
    #print(z3.simplify(c_in))
    #print(z3.simplify(c_out))
    of = ((c_0 ^ c_in) ^ c_out == 1)

    stack.append(z3.If(of, ONE, ZERO))

def do_DS(op, stack, state):
    ds = ((state.esil["cur"] >> (lastsz(state) - 1)) & ONE) == ONE
    stack.append(z3.If(ds, ONE, ZERO))

def do_S(op, stack, state):
    size, = pop_values(stack, state)
    s = ((state.esil["cur"] >> size) & ONE) == ONE
    stack.append(z3.If(s, ONE, ZERO))

# jump target??
def do_JT(op, stack, state):
    raise ESILUnimplementedException

def do_JS(op, stack, state):
    raise ESILUnimplementedException

# da fuq
def do_R(op, stack, state):
    stack.append(state.bits >> 3)

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
    "~": do_SIGN,
    "&": do_AND,
    "|": do_OR,
    "^": do_XOR,
    "+": do_ADD,
    "-": do_SUB,
    "*": do_MUL,
    "/": do_DIV,
    "%": do_MOD,
    "~/": do_SDIV,
    "~%": do_SMOD,
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

byte_vals = ["", "*", "1", "2", "4", "8", "16"]
op_vals = ["+", "-", "++", "--", "*", "/", "<<", ">>", "|", "&", "^", "%", "!", ">>>>", ">>>", "<<<"]

for op_val in op_vals:
    opcodes["%s=" % op_val] = do_OPEQ

for byte_val in byte_vals:
    opcodes["=[%s]" % byte_val] = do_POKE

    for op_val in op_vals:
        opcodes["%s=[%s]" % (op_val, byte_val)] = do_OPPOKE

for byte_val in byte_vals:
    opcodes["[%s]" % byte_val] = do_PEEK

