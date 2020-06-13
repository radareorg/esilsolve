
class ESILSim:

    def __init__(self, state):
        self.state = state
        self.memory = state.memory
        self.registers = state.registers
        self.r2api = state.r2api

    def __call__(self):
        pass

    def arg_count(self):
        func = self.__call__.__code__
        return func.co_argcount - 1