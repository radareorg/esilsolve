import solver
from copy import deepcopy

class ESILBitVecVal(solver.BitVecNumRef):

    def setName(self, name):
        self.name = name

class ESILBitVec(solver.BitVecRef):

    def setName(self, name):
        self.name = name

class ESILInt(int):
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

# this is gross but i dont want to have to wrap
# every single bv operation so...
def setRegisterName(bv, name):
    bv.__dict__["register"] = name

def getRegisterName(bv):
    return bv.__dict__["register"]

def setRegisterValue(reg_val, val, context):
    reg_name = getRegisterName(reg_val)
    register = context["registers"][reg_name]

    #reg_val = solver.BitVec(reg_name, reg_val.size)
    if type(val) == int:
        new_reg = solver.BitVecVal(val, register["size"])
    elif type(val) in [solver.BitVecNumRef, solver.BitVecRef]:
        new_reg = deepcopy(val) 
    else:
        raise ESILArgumentException

    setRegisterName(new_reg, reg_name)
    register["bv"] = new_reg

def newRegister(name, size, val=None):
    if val != None:
        new_reg = solver.BitVecVal(val, size)
    else:
        new_reg = solver.BitVec(name, size)

    setRegisterName(new_reg, name)
    return new_reg