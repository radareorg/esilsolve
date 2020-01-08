import solver
from copy import deepcopy

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


