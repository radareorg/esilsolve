from . import solver
from .esilclasses import *
import struct

BYTE = 8

class ESILMemory(dict):
    
    def __init__(self, r2api, info, sym=False):
        self._memory = {}
        self.r2api = r2api
        self.info = info
        self.pure_symbolic = sym
        self.default_addr = 0x100000

        self.multi_concretize = False # True destroys performance
        self.hit_symbolic_addr = False
        self.concrete_addrs = []

        self._needs_copy = False

        self.endian = info["info"]["endian"]
        self.bits = info["info"]["bits"]
        self.chunklen = int(self.bits/8)

        self.solver = None

    def mask(self, addr):
        return int(addr - (addr % self.chunklen))

    def bv_to_int(self, bv):
        bv = solver.simplify(bv)
        if solver.is_bv_value(bv):
            return bv.as_long()

        # this is terrible and temporary
        elif solver.is_bv(bv):
            print("symbolic addr: %s" % bv)
            self.hit_symbolic_addr = True
            sat = self.solver.check()
            if sat == solver.sat:
                model = self.solver.model()

                try:
                    val = model.eval(bv).as_long()
                    #print(val)

                    if self.multi_concretize:
                        self.solver.push()
                        self.solver.add(bv != val)
                        vals = solver.EvalMax(self.solver, bv)
                        if len(vals) > 0:
                            self.concrete_addrs.append({"bv": bv, "values": vals})
                        self.solver.pop()

                    self.solver.add(bv == val)
                    return val
                except:
                    # idk man i need a default value in case
                    # there are no constraints on the addr
                    return self.default_addr

    def read(self, addr, length):
        maddr = self.mask(addr)
        #print(maddr, length)

        data = []
        chunks = int(length/self.chunklen) + min(1, length%self.chunklen)
        #print(chunks)

        for chunk in range(chunks):
            caddr = maddr + chunk*self.chunklen
            if caddr in self._memory:
                data += self._memory[caddr]

            else:
                if self.pure_symbolic:
                    coffset = caddr+chunk*self.chunklen
                    bv = solver.BitVec("mem_%016x" % (coffset), self.chunklen*BYTE)
                    self.write_bv(addr, bv, self.chunklen)
                    d = self.unpack_bv(bv, self.chunklen)
                else:
                    d = self.r2api.read(caddr, self.chunklen)

                data += self.prepare_data(d)

        offset = addr-maddr
        #bv = solver.Concat(data[offset:offset+length])
        #print(self._memory)
        return data[offset:offset+length]


    def write(self, addr, data):

        if self._needs_copy:
            self._memory = deepcopy(self._memory)
            self._needs_copy = False

        data = self.prepare_data(data)
        maddr = self.mask(addr)
        offset = addr-maddr
        length = len(data)

        if maddr != addr or length % self.chunklen != 0:
            prev = self.read(maddr, length + (self.chunklen - (length % self.chunklen)))
            data = prev[:offset] + data + prev[offset+length:]

        chunks = int(length/self.chunklen) + min(1, length%self.chunklen)
        for chunk in range(chunks):
            o = chunk*self.chunklen
            caddr = maddr + o

            #print(caddr, data[o:o+self.chunklen])

            self._memory[caddr] = data[o:o+self.chunklen]

            #print(self._memory)

    def read_bv(self, addr, length):
        if type(addr) != int:
            addr = self.bv_to_int(addr)

        data = self.read(addr, length)
        bve = []

        if all(type(x) == int for x in data):
            bv = self.pack_bv(data)
            return bv 

        for datum in data:
            if type(datum) == int:
                bve.append(solver.BitVecVal(datum, BYTE))

            else:
                bve.append(datum)

        if self.endian == "little":
            bve.reverse()

        #print(bve)
        if len(bve) > 1:
            bv = solver.simplify(solver.Concat(*bve))
        else:
            bv = solver.simplify(bve[0])

        return bv

    def write_bv(self, addr, val, length):
        if type(addr) != int:
            addr = self.bv_to_int(addr)

        data = self.unpack_bv(val, length)
        self.write(addr, data)

    def pack_bv(self, data):
        val = 0
        for ind, dat in enumerate(data):
            val += dat << BYTE*ind

        return solver.BitVecVal(val, BYTE*len(data))

    def unpack_bv(self, val, length):
        data = []
        if type(val) == int:
            for i in range(length):
                data.append((val >> i*BYTE) & 0xff)

        else:
            val = solver.simplify(val) # useless?
            for i in range(length):
                data.append(solver.simplify(solver.Extract((i+1)*BYTE-1, i*BYTE, val)))

        if self.endian == "big":
            data.reverse()

        return data

    def prepare_data(self, data):
        return data

    def init_memory(self):
        pass

    def clone(self):
        clone = self.__class__(self.r2api, self.info, self.pure_symbolic)
        clone._needs_copy = True
        clone._memory = self._memory
        #clone._memory = deepcopy(self._memory)
        clone.endian = self.endian
        clone.bits = self.bits
        clone.chunklen = self.chunklen

        return clone