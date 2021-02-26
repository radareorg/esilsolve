import math
import z3
from .esilclasses import *
from .r2api import R2API

BYTE = 8

class ESILMemory:
    """ 
    Provides access to methods to read and write memory

    >>> state.memory[0xcafebabe]
    31337
    """

    def __init__(self, r2api: R2API, info: Dict, 
            max_eval=32, sym=False, check=False):

        self._memory = {}
        self._read_cache = {}
        self.r2api = r2api
        self.info = info
        self.pure_symbolic = sym
        self.check_perms = check
        self.max_eval = max_eval

        self._refs = {"count": 1}

        self.endian = info["info"]["endian"]
        self.bits = info["info"]["bits"]
        self.chunklen = int(self.bits/8)
        self.max_len = 4096
        self.error = z3.BitVecVal(self.max_len, 64) 
        # z3.BitVecVal((1<<(SIZE-1))-1, SIZE)

        self.solver = None

        self.heap = {} # this is it
        self.heap_start = 2 << (self.bits-8)
        self.heap_size = self.heap_start #idk
        self.heap_bin = 0x100
        self.heap_init = False

    def init_heap(self):
        segs = self.r2api.segments

        start = self.heap_start
        size = self.heap_size
        avail = False
        while not avail:
            avail = True
            for seg in segs:
                if (seg["addr"] < start < seg["addr"]+seg["size"] or 
                    start < seg["addr"] < start+size):

                        start = start+size
                        avail = False
                        break

        self.heap_start = start

        self.r2api.add_segment(
            "heap",
            self.heap_size,
            "-rw-",
            self.heap_start
        )
        self.heap_init = True

    def alloc(self, length=0x80):
        """ 
        The dumbest memory allocation function
        known to human or alien life

        >>> state.memory.alloc(0x100)
        0x02000100
        """

        if not self.heap_init:
            self.init_heap()
        
        needs = 0
        if isinstance(length, int):
            needs = int(length/self.heap_bin) + 1
        elif z3.is_bv_value(length):
            needs = int(length.as_long()/self.heap_bin) + 1
        else:
            more = True
            while more:
                needs += 1
                cur = z3.BitVecVal(needs*self.heap_bin, SIZE)
                more = (self.solver.check(length > cur) == z3.sat)
            
        slot = 0
        avail = False
        while not avail:
            unused = [(slot+i) not in self.heap for i in range(needs)]
            avail = all(unused)
            if not avail:
                slot += unused[::-1].index(False)+1
            else:
                new_slots = [(slot+i, slot) for i in range(needs)]
                self.heap.update(dict(new_slots))

        addr = self.heap_start + slot*self.heap_bin
        return addr

    def free(self, addr):

        if z3.is_bv(addr):
            addr = self.addr_to_int(addr)

        if addr == 0:
            return

        slot = int((addr-self.heap_start)/self.heap)
        if slot not in self.heap:
            print("%016x: double free?" % addr)
            return 

        cur = slot
        while True:
            if cur in self.heap and self.heap[cur] == slot:
                self.heap.pop(cur)
                cur += 1
            else:
                break

    def in_heap(self, addr):
        return self.heap_start+self.heap_size > addr > self.heap_start
    
    def mask(self, addr: int):
        return int(addr - (addr % self.chunklen))

    def addr_to_int(self, bv):

        if z3.is_bv_value(bv):
            return bv.as_long()
        
        bv = z3.simplify(bv)
        if z3.is_bv_value(bv):
            return bv.as_long()
        else: # should be only for free() now
            if self.solver.check() == z3.sat:
                model = self.solver.model()
                val = model.eval(bv, model_completion=True)
                self.solver.add(bv == val)
                return val.as_long()

            else:
                raise ESILUnsatException(
                    f"no sat symbolic address found for: {bv}")

    def read_con(self, addr: int, length: int):

        if self.check_perms:
            self.check(addr, "r")

        maddr = self.mask(addr)
        offset = addr-maddr
        #print(maddr, length)

        data = []
        chunks = math.ceil(float(length+offset)/self.chunklen)

        for chunk in range(chunks):
            caddr = maddr + chunk*self.chunklen
            if caddr in self._memory:
                data += self._memory[caddr]

            else:
                if self.pure_symbolic:
                    coffset = caddr+chunk*self.chunklen
                    bv = z3.BitVec("mem_%016x" % (coffset), self.chunklen*BYTE)
                    self.write_bv(addr, bv, self.chunklen)
                    d = self.unpack_bv(bv, self.chunklen)
                else:
                    if caddr in self._read_cache:
                        d = self._read_cache[caddr]
                    else:
                        d = self.r2api.read(caddr, self.chunklen)
                        self._read_cache[caddr] = d

                    self._memory[caddr] = d

                data += d

        return data[offset:offset+length]

    def eval_max(self, sym, n: int = 32):
        solutions = []

        self.solver.push()
        while len(solutions) < n:
            if self.solver.check() == z3.sat:
                m = self.solver.model()
                sol = m.eval(sym, True)
                solutions.append(sol)
                self.solver.add(sym != sol)
            else:
                break

        self.solver.pop()
        return solutions

    def read_bv(self, addr, length):
        if isinstance(addr, int):
            return self.pack_bv(self.cond_read(addr, length))
        elif z3.is_bv_value(addr):
            return self.pack_bv(self.cond_read(addr.as_long(), length))

        addr = z3.simplify(addr)
        if z3.is_bv_value(addr):
            return self.pack_bv(self.cond_read(addr.as_long(), length))

        addrs = self.eval_max(addr, self.max_eval)

        if addrs == []:
            raise ESILUnsatException("Unsat symbolic address")
        elif len(addrs) == 1:
            # should I add this constraint? no?
            return self.pack_bv(self.cond_read(addrs[0].as_long(), length))

        # constrain it to be one of these
        self.solver.add(z3.Or(*[addr == a for a in addrs]))

        result = None
        for address in addrs:
            val = self.pack_bv(self.cond_read(address.as_long(), length))

            if result == None:
                result = val
            else:
                result = z3.If(addr == address, val, result)

        return z3.simplify(result)

    def read(self, addr, length):
        if isinstance(addr, int):
            return self.cond_read(addr, length)
        elif z3.is_bv_value(addr):
            return self.cond_read(addr.as_long(), length)

        addr = z3.simplify(addr)
        if z3.is_bv_value(addr):
            return self.cond_read(addr.as_long(), length)

        data = self.read_bv(addr, length)
        return self.unpack_bv(data, int(data.size()/8))

    def write(self, addr, data):
        if isinstance(addr, int):
            return self.write_con(addr, data)
        elif z3.is_bv_value(addr):
            return self.write_con(addr.as_long(), data)
        
        addr = z3.simplify(addr)
        if z3.is_bv_value(addr):
            return self.write_con(addr.as_long(), data)

        addrs = self.eval_max(addr, self.max_eval)

        if addrs == []:
            raise ESILUnsatException("Unsat symbolic address")
        elif len(addrs) == 1:
            # should I add this constraint? no?
            return self.write_con(addrs[0].as_long(), data)

        # constrain it to be one of these
        self.solver.add(z3.Or(*[addr == a for a in addrs]))

        data = self.data_to_bv(data)
        length = int(data.size()/8)

        for address in addrs:
            addrint = address.as_long()
            val = self.pack_bv(self.cond_read(addrint, length))
            self.write_con(addrint, z3.If(addr == address, data, val))
        
    def write_bv(self, addr, data, length):
        data = self.unpack_bv(data, length)
        self.write(addr, data)

    def data_to_bv(self, data): 
        if z3.is_bv(data):
            return data
        elif isinstance(data, bytes):
            data = self.pack_bv(list(data))
        elif isinstance(data, str):
            data = self.pack_bv(list(data.encode())+[0]) # add null byte
        elif isinstance(data, int):
            data = BV(data, self.bits)

        return data
        
    def write_con(self, addr, data):

        if self._refs["count"] > 1:
            self.finish_clone()

        if self.check_perms:
            self.check(addr, "w")

        if z3.is_bv(data):
            length = int(data.size()/BYTE)
            data = self.unpack_bv(data, length)
        elif isinstance(data, bytes):
            data = list(data)
        elif isinstance(data, str):
            data = list(data.encode())+[0] # add null byte
        elif isinstance(data, int):
            data = self.unpack_bv(data, int(self.bits/8))

        data = self.prepare_data(data)
        maddr = self.mask(addr)
        offset = addr-maddr
        length = len(data)

        if maddr != addr or length % self.chunklen != 0:
            prev_len = length + (self.chunklen - (length % self.chunklen))
            prev = self.read(maddr, prev_len)
            data = prev[:offset] + data + prev[offset+length:]

        chunks = int(length/self.chunklen) + min(1, length%self.chunklen)
        for chunk in range(chunks):
            o = chunk*self.chunklen
            caddr = maddr + o

            self._memory[caddr] = data[o:o+self.chunklen]

    def memcopy(self, dst, src, length):
        length = z3.simplify(length)
        if z3.is_bv_value(length):
            data = self.read(src, length.as_long())
            self.write(dst, data)
        else:
            data = []
            for i in range(self.max_len):
                sc = self.read_bv(src+i, 1)
                dc = self.read_bv(dst+i, 1)
                new_len = z3.BitVecVal(i, SIZE)
                over_len = self.solver.check(length > new_len) == z3.unsat

                if not over_len:
                    data.append(z3.If(length > new_len, sc, dc))
                else:
                    break
                    
            self.write(dst, data)

    def move(self, dst, src, length):
        data = self.read(src, length)
        self.copy(dst, data, length)

    def copy(self, dst, data, length):
        length = z3.simplify(length)
        if z3.is_bv_value(length):
            self.write(dst, data[:length.as_long()])
        else:
            new_data = []
            for i in range(len(data)):
                sc = data[i]
                dc = self.read_bv(dst+i, 1)
                new_len = z3.BitVecVal(i, SIZE)
                over_len = self.solver.check(length > new_len) == z3.unsat

                if not over_len:
                    new_data.append(z3.If(length > new_len, sc, dc))
                else:
                    break
                    
            self.write(dst, new_data)

    def search(self, addr, needle, length=None, reverse=False):
        max_len = self.max_len
        n = len(needle)

        if n == 0:
            return ZERO

        if length != None:
            nbv = z3.BitVecVal(n-1, SIZE)
            length = z3.simplify(length-nbv)
            if z3.is_bv_value(length):
                max_len = length.as_long()

        else:
            length = z3.BitVecVal(max_len-n+1, SIZE)
        
        ret_ind = self.error # hmm idk
        ind_con = z3.BoolVal(False)

        rargs = (0, max_len, 1)
        if reverse:
            rargs = (max_len, 0, -1)

        for i in range(*rargs):
            cs = self.read(addr+i, n)
            found = all([
                (self.solver.check(cs[k] != needle[k]) == z3.unsat)
                for k in range(n)]) # oof

            not_found = any([
                (self.solver.check(cs[k] == needle[k]) == z3.unsat)
                for k in range(n)])

            new_ind = z3.BitVecVal(i, SIZE) 
            over_len = self.solver.check(length > new_ind) == z3.unsat

            if not over_len:
                if found:
                    ind_con = z3.And(length > new_ind, z3.Not(ind_con))
                    ret_ind = z3.If(ind_con, new_ind, ret_ind) 
                    return z3.simplify(ret_ind), i

                elif not not_found:
                    new_cons = [cs[k] == needle[k] for k in range(n)]
                    new_cons.append(length > new_ind)
                    new_con = z3.And(*new_cons)

                    ind_con = z3.And(new_con, z3.Not(ind_con))
                    ret_ind = z3.If(ind_con, new_ind, ret_ind)
            else:
                if not reverse:
                    return z3.simplify(ret_ind), i

        return z3.simplify(ret_ind), max_len

    def cond_read(self, addr, length):
        if isinstance(length, int):
            return self.read_con(addr, length)
        elif z3.is_bv_value(length):
            return self.read_con(addr, length.as_long())

        length = z3.simplify(length)
        if z3.is_bv_value(length):
            return self.read_con(addr, length.as_long())
        else:
            data = []
            for i in range(self.max_len):
                sc = self.read_con_bv(addr+i, 1)
                new_len = z3.BitVecVal(i, SIZE)
                over_len = self.solver.check(length > new_len) == z3.unsat

                if not over_len:
                    data.append(sc)
                else:
                    break

            return data

    def compare(self, s1, s2, length=None):
        max_len = self.max_len
        if length != None:
            length = z3.simplify(length)
            if z3.is_bv_value(length):
                max_len = length.as_long()

        else: # no len use null
            len1, last1 = self.search(s1, [BZERO])
            len2, last2 = self.search(s2, [BZERO])

            max_len = min(last1, last2)+1
            length = z3.If(len1 < len2, len1, len2)+1

        ret_val = ZERO
        for i in range(max_len):
            c1 = z3.ZeroExt(24, self.read_bv(s1+i, 1))
            c2 = z3.ZeroExt(24, self.read_bv(s2+i, 1))
            new_ind = z3.BitVecVal(i, SIZE)
            over_len = self.solver.check(length > new_ind) == z3.unsat

            if not over_len:
                this_val = z3.If(c1 == c2, ZERO, z3.If(c1 < c2, NEGONE, ONE))
                new_val = z3.If(ret_val == ZERO, this_val, ret_val)
                ret_val = z3.If(length > new_ind, new_val, ret_val) 
            else:
                break

        return z3.simplify(ret_val)

    def read_con_bv(self, addr, length):
        data = self.read_con(addr, length)
        return self.pack_bv(data)

    def write_con_bv(self, addr, val, length: int):
        data = self.unpack_bv(val, length)
        self.write_con(addr, data)

    def pack_bv(self, data):
        bve = []
        for d in data:
            if isinstance(d, int):
                bve.append(z3.BitVecVal(d, BYTE))
            else:
                bve.append(d)

        if self.endian == "little":
            bve.reverse()

        if len(bve) > 1:
            bv = z3.simplify(z3.Concat(*bve))
        else:
            bv = z3.simplify(bve[0])

        return bv

    def unpack_bv(self, val, length: int):
        if isinstance(val, int):
            data = [(val >> i*BYTE) & 0xff for i in range(length)]

        else:
            val = z3.simplify(val) # useless?
            data = [z3.Extract((i+1)*8-1, i*8, val) for i in range(length)]

        if self.endian == "big":
            data.reverse()

        return data

    def prepare_data(self, data):
        return data

    def check(self, addr, perm):
        perm_names = {
            "r": "read",
            "w": "write",
            "x": "execute"
        }

        perms = self.r2api.get_permissions(addr)
        if perm not in perms:
            raise ESILSegmentFault("failed to %s 0x%x (%s)" \
                % (perm_names[perm], addr, perms))

    def init_memory(self):
        pass

    def __getitem__(self, addr) -> z3.BitVecRef:
        length = self.chunklen
        if isinstance(addr, int) or z3.is_bv(addr):
            return self.read_bv(addr, length)
        elif isinstance(addr, str):
            addr = self.r2api.get_address(addr)
            return self.read_bv(addr, length)
        elif isinstance(addr, slice):
            length = int(addr.stop-addr.start)
            return self.read_bv(addr.start, length)

    def __setitem__(self, addr, value):
        if isinstance(addr, int) or z3.is_bv(addr):
            return self.write(addr, value)
        elif isinstance(addr, str):
            addr = self.r2api.get_address(addr)
            return self.write(addr, value)
        elif isinstance(addr, slice):
            length = int(addr.stop-addr.start)

            if isinstance(value, list):
                self.write(addr.start, value[:length])
            elif z3.is_bv(value):
                new_val = z3.Extract(length*8 - 1, 0, value)
                self.write(addr.start, new_val)

    def __contains__(self, addr: int) -> bool:
        return addr in self._memory

    def __iter__(self): 
        return iter(self._memory.keys())

    def clone(self):
        clone = self.__class__(self.r2api, self.info, 
            self.max_eval, self.pure_symbolic)

        self._refs["count"] += 1
        clone._refs = self._refs
        clone._memory = self._memory
        clone.heap = self.heap
        clone.heap_start = self.heap_start
        clone.heap_init = self.heap_init
        clone._read_cache = self._read_cache

        return clone

    def finish_clone(self):
        # we can do a shallow copy instead of deep
        self._memory = self._memory.copy()
        self.heap = self.heap.copy()
        self._refs["count"] -= 1
        self._refs = {"count": 1}