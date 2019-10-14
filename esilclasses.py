import solver
from copy import deepcopy

class ESILBitVecVal(solver.BitVecNumRef):

    def setName(self, name):
        self.name = name

class ESILBitVec(solver.BitVecRef):

    def setName(self, name):
        self.name = name

class ESILRegister(str):
    pass
    
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


