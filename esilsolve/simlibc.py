from z3.z3 import Distinct
from .esilclasses import *
import z3
import sys
import random
import time
import socket
import os
from struct import pack, unpack

def puts(state, addr):
    addr = state.evaluate(addr).as_long()
    length, last = state.mem_search(addr, [BZERO])
    data = state.mem_read(addr, length)
    state.fs.write(STDOUT, data)
    return length

def printf(state, addr, a1, a2, a3, a4, a5, a6, a7):
    addr = state.evaluate(addr).as_long()
    vargs = (a1,a2,a3,a4,a5,a6,a7)
    ##length, last = state.mem_search(addr, [BZERO])
    string, length = state.symbolic_string(addr)
    fmt = state.evaluate_string(string)
    data = list(format_writer(state, fmt, vargs).encode())
    state.fs.write(STDOUT, data)
    return len(data)

def memmove(state, dst, src, num):
    # evaluate and constrain
    # unconstrained memcpys will never be good
    state.mem_move(dst, src, num)
    return dst

def memcpy(state, dst, src, num):
    return state.mem_memcopy(dst, src, num)

def bcopy(state, src, dst, num):
    memcpy(state, dst, src, num)
    return ZERO

def bzero(state, dst, num):
    memset(state, dst, ZERO, num)
    return ZERO

def mempcpy(state, dst, src, num):
    return memcpy(state, dst, src, num) + num

def memccpy(state, dst, src, ch, num):
    c = z3.Extract(7, 0, ch)
    length, last = state.mem_search(src, [c], num)
    newlen = z3.If(length < num, length, num)
    result = mempcpy(state, dst, src, newlen)
    return z3.If(length == state.memory.error, ZERO, result)

def memfrob(state, addr, num):
    #state.proc.parse_expression( # this is the fun way to do it
    #"0,A1,-,DUP,DUP,?{,A1,-,A0,+,DUP,[1],0x2a,^,SWAP,=[1],1,+,1,GOTO,}", state)

    x = BV(0x2A, 8)
    data = [y^x for y in state.mem_read(addr, num)]
    state.mem_copy(addr, data, num)

def strlen(state, addr):
    length, last = state.mem_search(addr, [BZERO])
    return length
        
def strnlen(state, addr, n):
    length = strlen(state, addr)
    return z3.If(n < length, n, length)

def gets(state, addr): # just a maybe useful default
    length = state.fs.stdin_chunk
    read(state, STDIN, addr, length)
    return addr

def fgets(state, addr, length, f):
    fd = fileno(state, f)
    read(state, BV(fd), addr, length)
    return addr

def strcpy(state, dst, src):
    length, last = state.mem_search(src, [BZERO])
    state.mem_memcopy(dst, src, length+ONE)
    return dst

def stpcpy(state, dst, src):
    length, last = state.mem_search(src, [BZERO])
    return strcpy(state, dst, src) + length

def strdup(state, addr):
    length, last = state.mem_search(addr, [BZERO])
    new_addr = malloc(state, length)
    state.mem_move(new_addr, addr, length)
    return new_addr
 
def strdupa(state, addr):
    length, last = state.mem_search(addr, [BZERO])
    new_addr = malloc(state, length)
    state.mem_move(new_addr, addr, length)
    return new_addr+length

def strndup(state, addr, num):
    length, last = state.mem_search(addr, [BZERO])
    length = z3.If(num < length, num, length)
    new_addr = malloc(state, length)
    state.mem_move(new_addr, addr, length)
    return new_addr
 
def strndupa(state, addr, num):
    length, last = state.mem_search(addr, [BZERO])
    length = z3.If(num < length, num, length)
    new_addr = malloc(state, length)
    state.mem_move(new_addr, addr, length)
    return new_addr+length

def strfry(state, addr):
    length, last = state.mem_search(addr, [BZERO])
    data = state.mem_read(addr, length)
    # random.shuffle(data) # i dont actually want to do this?
    state.mem_copy(addr, data, length)
    return addr

def strncpy(state, dst, src, num):
    length, last = state.mem_search(src, [BZERO])
    # TODO this is not exactly right
    length = z3.If(num < length, num, length)
    state.mem_move(dst, src, length)
    return dst

def strcat(state, dst, src):
    dlength, last = state.mem_search(dst, [BZERO])
    dlength = state.evalcon(dlength).as_long()
    length, last = state.mem_search(src, [BZERO])
    state.mem_move(dst+dlength, src, length+ONE)
    return dst

def strncat(state, dst, src, num):
    dlength, last = state.mem_search(src, [BZERO])
    dlength = state.evalcon(dlength).as_long()
    length, last = state.mem_search(src, [BZERO])
    # TODO this is not exactly right
    length = z3.If(num < length, num, length)
    state.mem_move(dst+dlength, src, length+ONE)
    return dst

# I should really refactor this into
# a method in state.memory  
def memset(state, dst, ch, num): 
    c = z3.Extract(7, 0, ch) # TODO big endian

    length = z3.simplify(num)
    if z3.is_bv_value(length):
        state.mem_write(dst, [c]*length.as_long())
    else:
        data = []
        for i in range(state.max_len):
            dc = state.read_bv(dst+i, 1)
            new_len = BV(i, SIZE)
            over_len = state.solver.check(length > new_len) == z3.unsat

            if not over_len:
                data.append(z3.If(length > new_len, c, dc))
            else:
                break

        state.mem_write(dst, data)

    return dst

def memchr_help(state, dst, ch, num, reverse=False):
    c = z3.Extract(7, 0, ch) # TODO big endian
    #length = state.evalcon(num).as_long()
    index, last = state.mem_search(dst, [c], num, reverse)
    con = z3.And(index != state.memory.error, index < num)
    return z3.If(con, dst+index, ZERO)

def memchr(state, dst, ch, num):
    return memchr_help(state, dst, ch, num)

def memrchr(state, dst, ch, num):
    return memchr_help(state, dst, ch, num, True)

def strchr_help(state, dst, ch, reverse=False):
    c = z3.Extract(7, 0, ch) # TODO big endian
    length, zlast = state.mem_search(dst, [BZERO])
    index, last = state.mem_search(dst, [c], length, reverse)
    con = z3.And(index != state.memory.error, index < length)
    return z3.If(con, dst+index, ZERO)

def strchr(state, dst, ch):
    return strchr_help(state, dst, ch)

def strrchr(state, dst, ch):
    return strchr_help(state, dst, ch, reverse=True)

def memcmp(state, dst, src, num):
    return state.mem_compare(dst, src, num)

def strcmp(state, dst, src):
    return state.mem_compare(dst, src)

def strncmp(state, dst, src, num):
    slen, slast = state.mem_search(src, [BZERO])
    dlen, dlast = state.mem_search(dst, [BZERO])
    shorter = z3.If(dlen < slen, dlen, slen)
    num = z3.If(num < shorter, num+ONE, shorter+ONE)
    return state.mem_compare(dst, src, num)

def memmem(state, addr, dlen, needle, slen): 
    slen = state.evalcon(slen).as_long()
    data = state.mem_read(needle, slen)
    return state.mem_search(addr, data, dlen)

def strstr(state, addr, needle): # this is getting complicated and wrong
    slen, slast = state.mem_search(needle, [BZERO])
    data = state.mem_read(needle, slast)
    dlen, dlast = state.mem_search(addr, [BZERO])
    index, last = state.mem_search(addr, data, dlen)
    con = z3.And(index != state.memory.error, index+slen <= dlen)
    return z3.If(con, addr+index, ZERO)

def malloc(state, length):
    return state.mem_alloc(length)

def calloc(state, n, sz):
    return state.mem_alloc(n*sz)

def free(state, addr):
    state.mem_free(addr)
    return 0

def atoi_helper(state, addr, size=SIZE): # still sucks
    string, length = state.symbolic_string(addr)

    if z3.is_bv_value(string):
        cstr = state.evaluate_string(string)
        return BV(int(cstr), size)
    else:
        length = state.evalcon(length).as_long() # unfortunate

        result = BV(0, size)
        is_neg = z3.BoolVal(False)
        m = BV(ord("-"), 8)
        for i in range(length):
            d = state.mem_read_bv(addr+i, 1)
            is_neg = z3.If(d == m, z3.BoolVal(True), is_neg)
            c = z3.If(d == m, BV(0, size), z3.ZeroExt(size-8, d-BV_0))
            result = result+(c*BV(10**(length-(i+1)), size))

        result = z3.If(is_neg, -result, result)
        return result

def atoi(state, addr):
    return atoi_helper(state, addr, 32)

def atol(state, addr):
    return atoi_helper(state, addr, state.bits)

def atoll(state, addr):
    return atoi_helper(state, addr, 64)

def digit_to_char(digit):
    if digit < 10:
        return str(digit)

    return chr(ord('a') + digit - 10)

def str_base(number, base):
    if number < 0:
        return '-' + str_base(-number, base)

    (d, m) = divmod(number, base)
    if d > 0:
        return str_base(d, base) + digit_to_char(m)

    return digit_to_char(m)

def bvpow(bv, ex):
    nbv = BV(1, 128)
    for i in range(ex):
        nbv = nbv*bv
    
    return z3.simplify(nbv)

def itoa_helper(state, value, string, base, sign=True):
    # ok so whats going on here is... uhh it works
    data = [BZERO]
    nvalue = z3.SignExt(96, z3.Extract(31, 0, value))
    pvalue = z3.ZeroExt(64, value)
    do_neg = z3.And(nvalue < 0, base == 10, z3.BoolVal(sign))
    base = z3.ZeroExt(64, base)
    new_value = z3.If(do_neg, -nvalue, pvalue)
    shift = BV(0, 128)
    for i in range(32):
        d = (new_value % bvpow(base, i+1)) / bvpow(base, i)
        c = z3.Extract(7, 0, d)
        shift = z3.If(c == BZERO, shift+BV(8, 128), BV(0, 128))
        data.append(z3.If(c < 10, c+BV_0, (c-10)+BV_a))

    pbv = z3.Concat(*data)
    szdiff = pbv.size()-shift.size()
    pbv = pbv >> z3.ZeroExt(szdiff, shift)
    nbv = z3.simplify(z3.Concat(pbv, BV(ord("-"),8)))
    pbv = z3.simplify(z3.Concat(BV(0,8), pbv)) # oof
    state.mem_write(string, z3.If(do_neg, nbv, pbv))
        
    return string

def itoa(state, value, string, base):
    return itoa_helper(state, value, string, base)

def islower(state, ch):
    c = z3.Extract(7, 0, ch)
    return z3.If(z3.And(c >= BV_a, c <= BV_z), ONE, ZERO)

def isupper(state, ch):
    c = z3.Extract(7, 0, ch)
    return z3.If(z3.And(c >= BV_A, c <= BV_Z), ONE, ZERO)
    
def isalpha(state, ch):
    return isupper(state, ch) | islower(state, ch)

def isdigit(state, ch):
    c = z3.Extract(7, 0, ch)
    return z3.If(z3.And(c >= BV_0, c <= BV_9), ONE, ZERO)

def isalnum(state, ch):
    return isalpha(state, ch) | isdigit(state, ch)

def isblank(state, ch):
    c = z3.Extract(7, 0, ch)
    return z3.If(z3.Or(
        c == BV(ord(" "), 8), 
        c == BV(ord("\t"), 8)), ONE, ZERO)

def iscntrl(state, ch):
    c = z3.Extract(7, 0, ch)
    return z3.If(z3.Or(
        z3.And(c >= BV(0,8), c <= BV(0x1f,8)), 
        c == BV(0x7f, 8)), ONE, ZERO)

def toupper(state, ch):
    c = z3.Extract(7, 0, ch)
    is_lower = z3.And(c >= BV_a, c <= BV_z)
    c = z3.If(is_lower, (c-BV_a)+BV_A, c)
    return c

def tolower(state, ch):
    c = z3.Extract(7, 0, ch)
    is_upper = z3.And(c >= BV_A, c <= BV_Z)
    c = z3.If(is_upper, (c-BV_A)+BV_a, c)
    return c

def rand(state):
    # return random.randint(0, 2**32)
    r = random.randint(0, 2**32)
    return BV("rand_%08x" % r, 32)

def srand(state, s):
    s = state.evaluate(s).as_long()
    random.seed(s)
    return 1

def abs(state, i):
    i = z3.Extract(31, 0, i)
    return z3.If(i < 0, -i, i)

def labs(state, i):
    return z3.If(i < 0, -i, i)

def div(state, n, d):
    n = z3.Extract(31, 0, n)
    d = z3.Extract(31, 0, d)
    return (n/d)

def ldiv(state, n, d):
    return (n/d)

def fflush(state, f):
    sys.stdout.flush()
    return 0

def getpid(state):
    return state.pid

def fork(state):
    if state.fork_mode ==  "child":
        state.pid += 1
        return 0
    else:
        return state.pid+1

def getpagesize(state):
    return 0x1000 #idk

def gethostname(state, addr, size):
    size = state.evalcon(size).as_long()
    hostname = socket.gethostname()
    state.mem_write(addr, hostname[:size])
    return 0

def getenv(state, addr):
    name, length = state.symbolic_string(addr)
    con_name = state.evaluate_string(name)
    data = state.os.getenv(con_name)

    if data == None:
        return 0
    else:
        val_addr = state.mem_alloc(len(data)+1)
        state.memory[val_addr] = data
        return val_addr

def sleep(state, secs):
    if state.sleep:
        secs = state.evalcon(secs).as_long()
        time.sleep(secs)
        
    return 0

def fileno(state, f):
    # this isn't how its really done so ima leave this
    addr = state.evalcon(f).as_long()
    bv = state.memory[addr]
    return state.evalcon(bv).as_long()

def open(state, path, flags, mode):
    path = state.symbolic_string(path)[0]
    path_str = state.evaluate_string(path)
    flags = state.evalcon(flags).as_long()
    mode = state.evalcon(mode).as_long()
    return state.fs.open(path_str, flags, mode)

def mode_to_int(mode):
    m = 0

    if "rw" in mode:
        m |= os.O_RDWR
    elif "r" in mode:
        m |= os.O_RDONLY
    elif "w" in mode:
        m |= os.O_WRONLY
    elif "a" in mode:
        m |= os.O_APPEND

    if "+" in mode:
        m |= os.O_CREAT

    return m

def fopen(state, path, mode):
    f = state.mem_alloc(8)
    mode = state.evaluate_string(state.symbolic_string(path)[0])
    flags = mode_to_int(mode)
    fd = open(state, path, BV(flags), BV(0o777))
    state.memory[f] = fd
    return f

def close(state, fd):
    fd = state.evalcon(fd).as_long()
    return state.fs.close(fd)

def fclose(state, f):
    fd = fileno(state, f)
    return close(state, BV(fd))

def read(state, fd, addr, length):
    fd = state.evalcon(fd).as_long()
    #length = state.evalcon(length).as_long()
    length = z3.simplify(length)

    if z3.is_bv_value(length):
        rlen = length.as_long()
    else:
        rlen = len(state.mem_read(addr, length)) # hax

    data = state.fs.read(fd, rlen)
    dlen = BV(len(data))
    state.mem_copy(addr, data, length)
    return z3.If(dlen < length, dlen, length)

def fread(state, addr, sz, length, f):
    fd = fileno(state, f)
    return read(state, BV(fd), addr, sz*length)

def write(state, fd, addr, length):
    fd = state.evalcon(fd).as_long()
    length = state.evalcon(length).as_long()
    data = state.mem_read(addr, length)
    return state.fs.write(fd, data)

def fwrite(state, addr, sz, length, f):
    fd = fileno(state, f)
    return write(state, BV(fd), addr, sz*length)

def lseek(state, fd, offset, whence):
    fd = state.evalcon(fd).as_long()
    offset = state.evalcon(offset).as_long()
    whence = state.evalcon(whence).as_long()
    return state.fs.seek(fd, offset, whence)

def fseek(state, f, offset, whence):
    fd = fileno(state, f)
    return lseek(state, BV(fd), offset, whence)

def access(state, path, flag): # TODO: complete this
    path = state.symbolic_string(path)[0]
    path = state.evaluate_string(path)
    return state.fs.exists(path)

def stat(state, path, data): # TODO: complete this
    path = state.symbolic_string(path)[0]
    path = state.evaluate_string(path)
    return state.fs.exists(path)

def system(state, cmd):
    string, length = state.symbolic_string(cmd)
    print("system(%s)" % state.evaluate_string(string)) # idk
    return 0

def abort(state):
    print("process aborted")
    state.exit = 0
    return 0

def simexit(state, status):
    print("process exited")
    state.exit = status
    return 0

def print_stdout(s: str):
    try:
        from colorama import Fore, Style
        sys.stdout.write(Fore.YELLOW+s+Style.RESET_ALL)
    except:
        sys.stdout.write(s)

def nothin(state):
    return 0
    
def ret_one(state):
    return 1

def ret_negone(state):
    return BV(-1)

def ret_arg1(state, a):
    return a

def ret_arg2(state, a, b):
    return b

def ret_arg3(state, a, b, c):
    return c

def ret_arg4(state, a, b, c, d):
    return d

UINT = 0
SINT = 1
FLOAT = 2
PTR = 3

def ieee_to_float(endian, v, size=64):
    e = "<"
    if endian == "big":
        e = ">"

    o = e+"d"
    i = e+"Q"
    if size == 32:
        o = e+"f"
        i = e+"I"

    return unpack(o, pack(i, v))[0]

def convert_arg(state, arg, typ, size, base):

    szdiff = size-arg.size()

    if szdiff > 0:
        if typ == SINT:
            arg = z3.SignExt(szdiff, arg)
        else:
            arg = z3.ZeroExt(szdiff, arg)
    elif szdiff < 0:
        arg = z3.Extract(size-1, 0, arg)

    arg = state.evalcon(arg)
    if typ == UINT:
        return arg.as_long()
    elif typ == SINT:
        return arg.as_signed_long()
    elif typ == FLOAT:
        argl = arg.as_long()
        return ieee_to_float(state.endian, argl, size)
    else:
        addr = arg.as_long()
        string = state.symbolic_string(addr)[0]
        return state.evaluate_string(string)

# this sucks 
def format_writer(state, fmt, vargs):
    fmts = {
        "c":   ["c",  UINT,  8, 10],
        "d":   ["d",  SINT,  32, 10],
        "i":   ["i",  SINT,  32, 10],
        "u":   ["u",  UINT,  32, 10],
        "e":   ["e",  FLOAT, 64, 10],
        "E":   ["E",  FLOAT, 64, 10],
        "f":   ["f",  FLOAT, 32, 10],
        "lf":  ["lf", FLOAT, 64, 10],
        "Lf":  ["Lf", FLOAT, 64, 10],
        "g":   ["g",  FLOAT, 64, 10],
        "G":   ["G",  FLOAT, 64, 10],
        "hi":  ["hi", SINT,  16, 10],
        "hu":  ["hu", UINT,  16, 10],
        "lu":  ["lu", UINT,  state.bits, 10],
        "ld":  ["ld", SINT,  state.bits, 10],
        "li":  ["li", SINT,  state.bits, 10],
        "p":   ["x",  UINT,  state.bits, 16],
        "llu": ["lu", UINT,  64, 10],
        "lld": ["ld", SINT,  64, 10],
        "lli": ["li", SINT,  64, 10],
        "x":   ["x",  UINT,  32, 16],
        "hx":  ["x",  UINT,  16, 16],
        "lx":  ["x",  UINT,  state.bits, 16],
        "llx": ["x",  UINT,  64, 16],
        "o":   ["o",  UINT,  32, 8],
        "s":   ["s",  PTR,   state.bits, 10],
        #"n":   ["",  PTR,   state.bits, 10],
    }

    '''if fmt.count("%") == 1:
        r_str = ""
        p_ind = fmt.index("%")

        i = p_ind+1
        shiftstr = ""
        while not fmt[i].isalpha():
            shiftstr += fmt[i]
            i += 1'''

    new_args = []
    new_fmt = ""

    ind = 0
    argc = 0
    while ind < len(fmt):
        new_fmt += fmt[ind]
        if fmt[ind] != "%":  
            ind += 1
        else:  
            ind += 1
            nextc = fmt[ind:ind+1]
            if nextc == "%":
                new_fmt += nextc

            else:
                arg = vargs[argc]
                argc += 1

                while not nextc.isalpha():
                    new_fmt += nextc
                    ind += 1
                    nextc = fmt[ind:ind+1]
                
                next3fmt = fmt[ind:ind+3]
                next2fmt = fmt[ind:ind+2]
                next1fmt = fmt[ind:ind+1]

                if next3fmt in fmts:
                    rep, typ, sz, base = fmts[next3fmt]
                    new_args += [convert_arg(state, arg, typ, sz, base)]
                    new_fmt += rep
                    ind += 3

                elif next2fmt in fmts:
                    rep, typ, sz, base = fmts[next2fmt]
                    new_args += [convert_arg(state, arg, typ, sz, base)]
                    new_fmt += rep
                    ind += 2

                elif next1fmt in fmts:
                    rep, typ, sz, base = fmts[next1fmt]
                    new_args += [convert_arg(state, arg, typ, sz, base)]
                    new_fmt += rep
                    ind += 1
                
                elif next1fmt == "n":
                    lastind = len(new_fmt)-new_fmt[::-1].index("%")-1
                    n = len(new_fmt[:lastind]%tuple(new_args))
                    state.mem_write(arg, n)

    return new_fmt % tuple(new_args)

