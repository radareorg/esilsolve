from . import simlibc

syscalls = {
    "open" : simlibc.open,
    "close": simlibc.close,
    "read" : simlibc.read,
    "write": simlibc.write,
    "fork" : simlibc.fork,
    "exit" : simlibc.simexit
}