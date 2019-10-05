from esilclasses import *
from esilregisters import *
import solver

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
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1-arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LT(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1<arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LTE(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    state

    stack.append(arg1<=arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GT(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1>arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_GTE(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1>=arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LS(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1<<arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_RS(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1>>arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_LR(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(solver.RotateLeft(arg1, arg2))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_RR(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(solver.RotateRight(arg1, arg2))
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_AND(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1&arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_OR(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1|arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_XOR(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1^arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_ADD(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1+arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_SUB(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1-arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_MUL(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1*arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_DIV(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1/arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_MOD(op, stack, state):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1%arg2)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_NOT(op, stack, state):
    arg1 = stack.pop()
    stack.append(~arg1)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_INC(op, stack, state):
    arg1 = stack.pop()
    stack.append(arg1+1)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_DEC(op, stack, state):
    arg1 = stack.pop()
    stack.append(arg1-1)
    state.esil["old"] = arg1
    state.esil["cur"] = stack[-1]

def do_EQU(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    setRegisterValue(reg, val, state)
    state.esil["old"] = reg
    state.esil["cur"] = val

def do_ADDEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg+val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_SUBEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg-val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_MULEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg*val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_DIVEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg/val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_MODEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg%val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_LSEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg<<val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_RSEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg>>val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_ANDEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg&val)
    stack.append(reg)

    do_EQU(op, stack, state)

def do_OREQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg|val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_XOREQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(reg^val)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_INCEQ(op, stack, state):
    reg = stack.pop()

    stack.append(reg+1)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_DECEQ(op, stack, state):
    reg = stack.pop()

    stack.append(reg-1)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_NOTEQ(op, stack, state):
    reg = stack.pop()
    val = stack.pop()

    stack.append(~reg, state)
    stack.append(reg)
    do_EQU(op, stack, state)

def do_SWAP(op, stack, state):
    reg1 = stack.pop()
    reg2 = stack.pop()

    # this looks wrong but its not (i think)
    setRegisterValue(reg1, reg2, state)
    setRegisterValue(reg2, reg1, state)

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
    addr = stack.pop()
    data = stack.pop()

    state.memory.writeBV(addr, data, length)
    state.esil["old"] = addr

def do_PEEK(op, stack, state):
    length = memlen(op)
    addr = stack.pop()

    data = state.memory.readBV(addr, length)
    stack.append(data)
    state.esil["old"] = addr
    state.esil["cur"] = stack[-1]

def do_NOMBRE(op, stack, state):
    raise ESILUnimplementedException

def do_NOP(op, stack, state):
    pass


def genmask(bits):
    m = (2 << 63) - 1
    if(bits > 0 and bits < 64):
        m = (2 << bits) - 1
    
    return m

def lastsz(state):
    old = state.esil["old"]
    cur = state.esil["cur"]

    try:
        return old.size()
    except:
        pass
    
    try:
        return cur.size()
    except:
        pass
    
    return state.info["bits"]

# flag op functions
# jesus h g wells christ these are gross
def do_ZF(op, stack, state):
    eq = (state.esil["cur"] == 0) # 
    #stack.append(eq)
    stack.append(solver.If(eq, solver.BitVecVal(1, 1), solver.BitVecVal(0, 1)))
    
def do_CF(op, stack, state):
    bits = stack.pop()
    mask = genmask(bits & 0x3f)
    cf = (state.esil["cur"] & mask) < (state.esil["old"] & mask)
    stack.append(solver.If(cf, solver.BitVecVal(1, 1), solver.BitVecVal(0, 1)))

def do_B(op, stack, state):
    bits = stack.pop()
    mask = genmask((bits + 0x3f) & 0x3f)
    bf = (state.esil["old"] & mask) < (state.esil["cur"] & mask)
    stack.append(solver.If(bf, solver.BitVecVal(1, 1), solver.BitVecVal(0, 1)))

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
    c1 = 0x0101010101010101
    c2 = 0x8040201008040201
    c3 = 0x1FF

    lsb = state.esil["cur"] & 0xff
    pf = (~((((lsb * c1) & c2) % c3) & 1) == 1)
    stack.append(solver.If(pf, solver.BitVecVal(1, 1), solver.BitVecVal(0, 1)))

def do_O(op, stack, state):
    try:
        old = state.esil["old"]
        cur = state.esil["cur"]
        sz = lastsz(state)
        m = [sz-1, sz-2]
        of = (((cur & m[0]) < (old & m[0])) ^ ((cur & m[1]) < (old & m[1])) == 1)

        stack.append(solver.If(of, solver.BitVecVal(1, 1), solver.BitVecVal(0, 1)))
    except:
        stack.append(solver.BitVecVal(0, 1))

def do_DS(op, stack, state):
    ds = ((state.esil["cur"] >> (lastsz(state) - 1)) & 1) == 1
    return stack.append(solver.If(ds, solver.BitVecVal(1, 1), solver.BitVecVal(0, 1)))

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
    ">>": do_RS,
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
    ":=": do_EQU,
    "+=": do_ADDEQ,
    "-=": do_SUBEQ,
    "*=": do_MULEQ,
    "/=": do_DIVEQ,
    "%=": do_MODEQ,
    "<<=": do_LSEQ,
    ">>=": do_RSEQ,
    "&=": do_ANDEQ,
    "|=": do_OREQ,
    "^=": do_XOREQ,
    "++=": do_INCEQ,
    "--=": do_DECEQ,
    "!=": do_NOTEQ,
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
    "$ds": do_DS,
    "$jt": do_JT,
    "$js": do_JS,
    "$r": do_R,
}

byte_vals = ["", "*", "1", "2", "4", "8"]

for byte_val in byte_vals:
    opcodes["=[%s]" % byte_val] = do_POKE

for byte_val in byte_vals:
    opcodes["[%s]" % byte_val] = do_PEEK

#for byte_val in byte_vals:
#    opcodes["|=[%s]" % byte_val] = do_NOMBRE # idk what this is
