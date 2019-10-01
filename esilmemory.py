import solver
from esilclasses import *
import struct

BYTE = 8

class ESILMemory(dict):
    
    def __init__(self, r2api, info):
        self._memory = {}
        self.r2api = r2api

        self.endian = info["info"]["endian"]
        self.bits = info["info"]["bits"]
        self.chunklen = int(self.bits/8)


    def mask(self, addr):
        return int(addr - (addr % self.chunklen))

    def read(self, addr, length):
        maddr = self.mask(addr)

        data = []
        chunks = int(length/self.chunklen) + min(1, length%self.chunklen)

        for chunk in range(chunks):
            caddr = maddr + chunk*self.chunklen
            if caddr in self._memory:
                data += self._memory[caddr]

            else:
                d = self.r2api.read(caddr, self.chunklen)
                data += self.prepareData(d)

        offset = addr-maddr
        #bv = solver.Concat(data[offset:offset+length])
        return data[offset:offset+length]


    def write(self, addr, data):
        data = self.prepareData(data)
        maddr = self.mask(addr)
        offset = addr-maddr
        length = len(data)

        if maddr != addr or length % self.chunklen != 0:
            prev = self.read(addr, length)
            data = prev[:offset] + data + prev[offset+length:]

        chunks = int(length/self.chunklen) + min(1, length%self.chunklen)
        for chunk in range(chunks):
            o = chunk*self.chunklen
            caddr = maddr + o

            self._memory[caddr] = data[o:self.chunklen]

    def readBV(self, addr, length):
        data = self.read(addr, length)

        bve = []

        if all(type(x) == int for x in data):
            bv = self.packBV(data)
            return bv 

        for datum in data:
            if type(datum) == int:
                bve.append(solver.BitVecVal(datum, BYTE))

            else:
                bve.append(datum)

        bve.reverse()
        bv = solver.Concat(bve)
        return bv

    def writeBV(self, addr, val, length):

        data = self.unpackBV(val, length)
        self.write(addr, data)

    def packBV(self, data):
        val = 0
        for ind, dat in enumerate(data):
            val += dat << BYTE*ind

        return solver.BitVecVal(val, BYTE*len(data))

    def unpackBV(self, val, length):
        data = []
        if type(val) == int:
            for i in range(length):
                data.append((val >> i*BYTE) & 0xff)

        else:
            for i in range(length):
                data.append(solver.Extract((i+1)*BYTE-1, i*BYTE, val))

        if self.endian == "big":
            data.reverse()

        return data

    def prepareData(self, data):
        return data
