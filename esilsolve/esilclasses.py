import z3
from enum import Enum

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

class ESILSolveEvent(Enum):
    SymExec  = 1
    SymRead  = 2
    SymWrite = 3
    SymFree  = 4
    # free gets its own event because idk
    # it will be useful for heap vulns

from typing import Union, List, Dict, Callable

class EventContext:
    address: z3.BitVecRef = None
    length: Union[z3.BitVecRef, int] = None
    data: Union[z3.BitVecRef, List] = None

    def __init__(self, addr, length=None, data=None):
        self.address = addr
        self.length = length
        self.data = data

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
