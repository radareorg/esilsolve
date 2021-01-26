import z3

class ESILTrapException(Exception):
    pass

class ESILBreakException(Exception):
    pass

class ESILTodoException(Exception):
    pass

class ESILArgumentException(Exception):
    pass

class ESILUnimplementedException(Exception):
    pass

class ESILUnsatException(Exception):
    pass

class ESILSegmentFault(Exception):
    pass

from typing import Union, List, Dict, Callable

# addresses can by flag names or ints
Address = Union[str, int]
HookTarget = Union[str, int, Callable]

SIZE = 64

def BV(val: Union[str, int], size: int=SIZE):
    if type(val) == int:
        return z3.BitVecVal(val, size)
    else:
        return z3.BitVec(val, size)

ONE = BV(1)
ZERO = BV(0)
NEGONE = BV(-1)

BZERO = BV(0, 8)

BV_A = BV(ord("A"), 8)
BV_Z = BV(ord("Z"), 8)
BV_a = BV(ord("a"), 8)
BV_z = BV(ord("z"), 8)
BV_0 = BV(ord("0"), 8)
BV_9 = BV(ord("9"), 8)

STDIN  = 0
STDOUT = 1
STDERR = 2

def recursive_if(val, opts, default=BV(0)):
    if len(opts) > 0:
        opt = opts[0]
        opts.remove(opt)
        val = z3.If(val == opt[0], opt[1], 
            recursive_if(val, opts, default))
    else:
        return default
