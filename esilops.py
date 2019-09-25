from esilclasses import *
import solver

def do_TRAP(op, stack, context):
    raise ESILTrapException

def do_BREAK(op, stack, context):
    raise ESILBreakException

def do_TODO(op, stack, context):
    raise ESILTodoException

def do_SYS(op, stack, context):
    raise ESILUnimplementedException

def do_PCADDR(op, stack, context):
    raise ESILUnimplementedException

def do_CMP(op, stack, context):
    raise ESILUnimplementedException

def do_LT(op, stack, context):
    raise ESILUnimplementedException

def do_LTE(op, stack, context):
    raise ESILUnimplementedException

def do_GT(op, stack, context):
    raise ESILUnimplementedException

def do_GTE(op, stack, context):
    raise ESILUnimplementedException

def do_LS(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    arg1.value<<arg2.value
    stack.append()

def do_RS(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1>>arg2)

def do_LR(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(solver.RotateLeft(arg1, arg2))

def do_RR(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(solver.RotateRight(arg1, arg2))

def do_AND(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1&arg2)

def do_OR(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1|arg2)

def do_XOR(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1^arg2)

def do_ADD(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1+arg2)

def do_SUB(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1-arg2)

def do_MUL(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1*arg2)

def do_DIV(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1/arg2)

def do_MOD(op, stack, context):
    arg1 = stack.pop()
    arg2 = stack.pop()

    stack.append(arg1%arg2)

def do_NOT(op, stack, context):
    arg1 = stack.pop()
    stack.append(solver.Not(arg1))

def do_INC(op, stack, context):
    arg1 = stack.pop()
    stack.append(arg1+1)

def do_DEC(op, stack, context):
    arg1 = stack.pop()
    stack.append(arg1-1)

def do_EQU(op, stack, context):
    reg = stack.pop()
    val = stack.pop()

    setRegisterValue(reg, val, context)

def do_ADDEQ(op, stack, context):
    raise ESILUnimplementedException

def do_SUBEQ(op, stack, context):
    raise ESILUnimplementedException

def do_MULEQ(op, stack, context):
    raise ESILUnimplementedException

def do_DIVEQ(op, stack, context):
    raise ESILUnimplementedException

def do_MODEQ(op, stack, context):
    raise ESILUnimplementedException

def do_LSEQ(op, stack, context):
    raise ESILUnimplementedException

def do_RSEQ(op, stack, context):
    raise ESILUnimplementedException

def do_ANDEQ(op, stack, context):
    raise ESILUnimplementedException

def do_OREQ(op, stack, context):
    raise ESILUnimplementedException

def do_XOREQ(op, stack, context):
    raise ESILUnimplementedException

def do_INCEQ(op, stack, context):
    raise ESILUnimplementedException

def do_DECEQ(op, stack, context):
    raise ESILUnimplementedException

def do_NOTEQ(op, stack, context):
    raise ESILUnimplementedException

def do_SWAP(op, stack, context):
    raise ESILUnimplementedException

def do_PICK(op, stack, context):
    raise ESILUnimplementedException

def do_RPICK(op, stack, context):
    raise ESILUnimplementedException

def do_DUP(op, stack, context):
    raise ESILUnimplementedException

def do_NUM(op, stack, context):
    raise ESILUnimplementedException

def do_CLEAR(op, stack, context):
    raise ESILUnimplementedException

def do_BREAK(op, stack, context):
    raise ESILUnimplementedException

def do_GOTO(op, stack, context):
    raise ESILUnimplementedException

def do_POKE(op, stack, context):
    raise ESILUnimplementedException

def do_PEEK(op, stack, context):
    raise ESILUnimplementedException

def do_NOMBRE(op, stack, context):
    raise ESILUnimplementedException

def do_NOP(op, stack, context):
    pass

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
    "": do_NOP
}

byte_vals = ["", "*", "1", "2", "4", "8"]

for byte_val in byte_vals:
    opcodes["=[%s]" % byte_val] = do_POKE

for byte_val in byte_vals:
    opcodes["[%s]" % byte_val] = do_PEEK

for byte_val in byte_vals:
    opcodes["|=[%s]" % byte_val] = do_NOMBRE # idk what this is
