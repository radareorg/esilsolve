from .esilclasses import *
import os
import sys
import z3

# TODO: handle env, sys info, user/perm stuff, other things?
class ESILOS:
    def __init__(self, r2api, init=True, **kwargs):
        self.kwargs = kwargs
        self.env = {}
        self._needs_copy = False
        self.info = r2api.get_info()
        self.endian = self.info["info"]["endian"]

        if init:
            for var in os.environ:
                self.env[var] = list(os.environ[var].encode())

    def getenv(self, name):
        if name in self.env:
            return self.env[name]

    def setenv(self, name, val):
        if self._needs_copy:
            self.finish_clone()

        self.env[name] = self.convert_data(val)

    # make data into nice lists
    def convert_data(self, val):
        if type(val) == int:
            data = [(val >> i*8) & 0xff for i in range(8)]

        elif type(val) == list:
            return val

        elif type(val) == bytes:
            return list(val)

        elif type(val) == str:
            return list(val.encode())

        else:
            val = z3.simplify(val) # useless?
            data = [z3.Extract((i+1)*8-1, i*8, val) 
                for i in range(int(val.size()/8))]

        if self.endian == "big":
            data.reverse()

        return data 

    def clone(self):
        clone = self.__class__(self.r2api, False, **self.kwargs)
        clone.env = self.env
        clone._needs_copy = True
        return clone

    def finish_clone(self):
        self.env = self.env.copy()
        self._needs_copy = False