from .esilclasses import *
import z3
import sys
import random
import time
import socket

def puts(state, s):
    addr = state.evaluate(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    data = state.memory.cond_read(addr, length)
    state.fs.write(1, data)
    return length

def memmove(state, dst, src, num):
    # evaluate and constrain
    # unconstrained memcpys will never be good
    dst = state.evalcon(dst).as_long()
    src = state.evalcon(src).as_long()
    state.memory.move(dst, src, num)
    return dst

def memcpy(state, dst, src, num):
    dst = state.evalcon(dst).as_long()
    src = state.evalcon(src).as_long()
    return state.memory.memcopy(dst, src, num)

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
    s = state.evalcon(src).as_long()
    length, last = state.memory.search(s, [c], num)
    newlen = z3.If(length < num, length, num)
    result = mempcpy(state, dst, src, newlen)
    return z3.If(length == state.memory.error, ZERO, result)

def memfrob(state, dst, num):
    addr = state.evalcon(dst).as_long()
    #state.proc.parse_expression( # this is the fun way to do it
    #    "0,A1,-,DUP,DUP,?{,A1,-,A0,+,DUP,[1],0x2a,^,SWAP,=[1],1,+,1,GOTO,}", state)

    x = BV(0x2A, 8)
    data = [y^x for y in state.memory.cond_read(addr, num)]
    state.memory.copy(addr, data, num)

def strlen(state, s):
    addr = state.evalcon(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    return length
        
def strnlen(state, s, n):
    length = strlen(state, s)
    return z3.If(n < length, n, length)

def gets(state, s): # just a maybe useful default
    addr = state.evalcon(s).as_long()
    length = state.fs.stdin_chunk
    data = BV("gets_%08x" % addr, length)
    state.write_stdin(data)
    read(state, 0, addr, length)
    return s

def strcpy(state, dst, src):
    dst = state.evalcon(dst).as_long()
    src = state.evalcon(src).as_long()
    length, last = state.memory.search(src, [BZERO])
    state.memory.memcopy(dst, src, length+ONE)
    return dst

def stpcpy(state, dst, src):
    addr = state.evalcon(src).as_long()
    length, last = state.memory.search(addr, [BZERO])
    return strcpy(state, dst, src) + length

def strdup(state, s):
    addr = state.evalcon(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    new_addr = malloc(state, length)
    state.memory.move(new_addr, addr, length)
    return new_addr
 
def strdupa(state, s):
    addr = state.evalcon(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    new_addr = malloc(state, length)
    state.memory.move(new_addr, addr, length)
    return new_addr+length

def strndup(state, s, num):
    addr = state.evalcon(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    length = z3.If(num < length, num, length)
    new_addr = malloc(state, length)
    state.memory.move(new_addr, addr, length)
    return new_addr
 
def strndupa(state, s, num):
    addr = state.evalcon(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    length = z3.If(num < length, num, length)
    new_addr = malloc(state, length)
    state.memory.move(new_addr, addr, length)
    return new_addr+length

def strfry(state, s):
    addr = state.evalcon(s).as_long()
    length, last = state.memory.search(addr, [BZERO])
    data = state.memory.cond_read(addr, length)
    # random.shuffle(data) # i dont actually want to do this?
    state.memory.copy(addr, data, length)
    return s

def strncpy(state, dst, src, num):
    dst = state.evalcon(dst).as_long()
    src = state.evalcon(src).as_long()
    length, last = state.memory.search(src, [BZERO])
    # TODO this is not exactly right
    length = z3.If(num < length, num, length)
    state.memory.move(dst, src, length)
    return dst

def strcat(state, dst, src):
    dst = state.evalcon(dst).as_long()
    dlength, last = state.memory.search(dst, [BZERO])
    dlength = state.evalcon(dlength).as_long()
    src = state.evalcon(src).as_long()
    length, last = state.memory.search(src, [BZERO])
    state.memory.move(dst+dlength, src, length+ONE)
    return dst

def strncat(state, dst, src, num):
    dst = state.evalcon(dst).as_long()
    dlength, last = state.memory.search(src, [BZERO])
    dlength = state.evalcon(dlength).as_long()
    src = state.evalcon(src).as_long()
    length, last = state.memory.search(src, [BZERO])
    # TODO this is not exactly right
    length = z3.If(num < length, num, length)
    state.memory.move(dst+dlength, src, length+ONE)
    return dst

# I should really refactor this into
# a method in state.memory  
def memset(state, dst, ch, num): 
    dst = state.evalcon(dst).as_long()
    c = z3.Extract(7, 0, ch) # TODO big endian

    length = z3.simplify(num)
    if z3.is_bv_value(length):
        state.memory.write(dst, [c]*length.as_long())
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

        state.memory.write(dst, data)

    return dst

def memchr_help(state, dst, ch, num, reverse=False):
    addr = state.evalcon(dst).as_long()
    c = z3.Extract(7, 0, ch) # TODO big endian
    #length = state.evalcon(num).as_long()
    index, last = state.memory.search(addr, [c], num, reverse)
    con = z3.And(index != state.memory.error, index < num)
    return z3.If(con, dst+index, ZERO)

def memchr(state, dst, ch, num):
    return memchr_help(state, dst, ch, num)

def memrchr(state, dst, ch, num):
    return memchr_help(state, dst, ch, num, True)

def strchr_help(state, dst, ch, reverse=False):
    addr = state.evalcon(dst).as_long()
    c = z3.Extract(7, 0, ch) # TODO big endian
    length, zlast = state.memory.search(addr, [BZERO])
    index, last = state.memory.search(addr, [c], length, reverse)
    con = z3.And(index != state.memory.error, index < length)
    return z3.If(con, dst+index, ZERO)

def strchr(state, dst, ch):
    return strchr_help(state, dst, ch)

def strrchr(state, dst, ch):
    return strchr_help(state, dst, ch, reverse=True)

def memcmp(state, dst, src, num):
    s1 = state.evalcon(dst).as_long()
    s2 = state.evalcon(src).as_long()
    return state.memory.compare(s1, s2, num)

def strcmp(state, dst, src):
    s1 = state.evalcon(dst).as_long()
    s2 = state.evalcon(src).as_long()
    return state.memory.compare(s1, s2)

def strncmp(state, dst, src, num):
    s1 = state.evalcon(dst).as_long()
    s2 = state.evalcon(src).as_long()
    slen, slast = state.memory.search(s2, [BZERO])
    dlen, dlast = state.memory.search(s1, [BZERO])
    shorter = z3.If(dlen < slen, dlen, slen)
    num = z3.If(num < shorter, num+ONE, shorter+ONE)
    return state.memory.compare(s1, s2, num)

def memmem(state, dst, dlen, src, slen): 
    addr = state.evalcon(dst).as_long()
    needle = state.evalcon(src).as_long()
    slen = state.evalcon(slen).as_long()
    data = state.memory.read(needle, slen)
    return state.memory.search(addr, data, dlen)

def strstr(state, dst, src): # this is getting complicated and wrong
    addr = state.evalcon(dst).as_long()
    needle = state.evalcon(src).as_long()
    slen, slast = state.memory.search(needle, [BZERO])
    data = state.memory.read(needle, slast)
    dlen, dlast = state.memory.search(addr, [BZERO])
    index, last = state.memory.search(addr, data, dlen)
    con = z3.And(index != state.memory.error, index+slen <= dlen)
    return z3.If(con, dst+index, ZERO)

def malloc(state, length):
    return state.memory.alloc(length)

def calloc(state, n, sz):
    return state.memory.alloc(n*sz)

def free(state, addr):
    addr = state.evalcon(addr).as_long()
    state.memory.free(addr)
    return 0

def atoi_helper(state, s, size=SIZE): # still sucks
    addr = state.evalcon(s).as_long()
    string, length = state.symbolic_string(addr)

    if z3.is_bv_value(string):
        cstr = state.evaluate_string(string)
        return BV(int(cstr), size)
    else:
        length = state.evalcon(length).as_long() # unfortunate

        result = BV(0, size)
        for i in range(length):
            d = state.memory.read_bv(addr+i, 1)
            c = z3.ZeroExt(size-8, d-BV_0)
            result = result+(c*BV(10**(length-i), size))

        return result

def atoi(state, s):
    atoi_helper(state, s, 32)

def atol(state, s):
    atoi_helper(state, s, state.bits)

def atoll(state, s):
    atoi_helper(state, s, 64)

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
    addr = state.evalcon(addr).as_long()
    size = state.evalcon(size).as_long()
    hostname = socket.gethostname()
    state.memory[addr] = hostname[:size]
    return 0x1000 #idk

def sleep(state, secs):
    if state.sleep:
        secs = state.evalcon(secs).as_long()
        time.sleep(secs)
        
    return 0

def open(state, path, flags, mode):
    path = state.evalcon(path).as_long()
    path_str = state.evaluate_string(state.symbolic_string(path)[0])
    flags = state.evalcon(flags).as_long()
    mode = state.evalcon(mode).as_long()
    return state.fs.open(path_str, flags, mode)

def close(state, fd):
    fd = state.evalcon(fd).as_long()
    return state.fs.close(fd)

def read(state, fd, addr, length):
    fd = state.evalcon(fd).as_long()
    addr = state.evalcon(addr).as_long()
    #length = state.evalcon(length).as_long()
    length = z3.simplify(length)

    if z3.is_bv_value(length):
        rlen = length.as_long()
    else:
        rlen = len(state.memory.cond_read(addr, length)) # hax

    data = state.fs.read(fd, rlen)
    dlen = BV(len(data))
    state.memory.copy(addr, data, length)
    return z3.If(dlen < length, dlen, length)

def write(state, fd, addr, length):
    fd = state.evalcon(fd).as_long()
    addr = state.evalcon(addr).as_long()
    length = state.evalcon(length).as_long()
    data = state.memory.read(addr, length)
    return state.fs.write(fd, data)

def lseek(state, fd, offset, whence):
    fd = state.evalcon(fd).as_long()
    offset = state.evalcon(offset).as_long()
    whence = state.evalcon(whence).as_long()
    return state.fs.seek(fd, offset, whence)

def access(state, path, flag): # TODO: complete this
    path = state.evalcon(path).as_long()
    path = state.evaluate_string(state.symbolic_string(path)[0])
    return state.fs.exists(path)

def stat(state, path, data): # TODO: complete this
    path = state.evaluate_string(state.symbolic_string(path)[0])
    return state.fs.exists(path)

def system(state, cmd):
    addr = state.evalcon(cmd).as_long()
    string, length = state.symbolic_string(addr)
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
    
def ret_arg1(state, a):
    return a

def ret_arg2(state, a, b):
    return b

def ret_arg3(state, a, b, c):
    return c

def ret_arg4(state, a, b, c, d):
    return d

def format_helper(state, fmt, vargs, write=True):
    data = []
    replacements = {}
    return data
