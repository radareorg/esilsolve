from .esilclasses import *
import os
import sys
import z3

class ESILFilesystem:
    
    def __init__(self, r2api, init=True, **kwargs):
        self.kwargs = kwargs
        self.r2api = r2api
        self.real = kwargs.get("realfs", False)
        self.realstd = kwargs.get("realstd", False)
        self.std = (STDIN, STDOUT, STDERR)
        # fd_dict[i] == [position, length, path, mode, content]
        # file_dict[path] == [length, content]
        self.file_dict = {}
        self.fd_dict = {}
        self.info = r2api.get_info()
        self.endian = self.info["info"]["endian"]
        self.symbolic_file_limit = kwargs.get("sym_file", 4096)
        self.max_fds = kwargs.get("max_fds", 4096)
        self.stdin_chunk = kwargs.get("stdin_chunk", 1024)

        self._needs_copy = False

        if init:
            self.fd_dict = { 
                STDIN  : [0, 0, "", os.O_RDONLY, []],
                STDOUT : [0, 0, "", os.O_WRONLY, []],
                STDERR : [0, 0, "", os.O_WRONLY, []]
            }

    def get_fd(self):
        for fd in range(self.max_fds):
            if fd not in self.fd_dict:
                return fd

        return -1

    def exists(self, path):
        if self.real:
            return int(os.path.exists(path))
        else:
            return int(path in self.file_dict)

    def stat(self, path): # TODO: this 
        if self.exists(path):
            return 0
        else:
            return -1

    def unlink(self, path):
        if self.exists(path):
            if self.real:
                os.unlink(path)
            else:
                self.file_dict.pop(path)

            return 0
        else:
            return -1

    def open(self, path, flags, mode):
        fd = -1
        if not self.real and path in self.file_dict:
            if self._needs_copy:
                self.finish_clone()

            f = self.file_dict[path]
            fd = self.get_fd()
            self.fd_dict[fd] = [
                0, len(f), path, flags, f
            ]

            if flags | os.O_APPEND:
                self.fd_dict[fd][0] = self.fd_dict[fd][1]
        
        elif self.real:
            if os.path.exists(path) or flags | os.O_CREAT:
                fd = os.open(path, flags, mode)
        
        return fd

    def close(self, fd):
        if self.real:
            return os.close(fd)
        else:
            if self._needs_copy:
                self.finish_clone()

            if fd < 3:
                return -1
            else:
                if fd in self.fd_dict:
                    f = self.fd_dict[fd]
                    self.file_dict[f[2]] = f[-1] 
                    self.fd_dict.pop(fd)
                
                return 0

    def seek(self, fd, offset=None, whence=None):
        if self.real:
            return os.lseek(fd, offset, whence)
        else:
            if self._needs_copy:
                self.finish_clone()

            if offset == None:
                return self.fd_dict[fd][0]
            else:
                self.fd_dict[fd][0] = offset
                return offset

    # length must be int
    def read(self, fd, length):
        if self.real or (self.realstd and fd in self.std):
            return list(os.read(fd, length))
        else:
            if self._needs_copy:
                self.finish_clone()

            f = self.fd_dict[fd]
            pos = f[0]
            f[0] = f[0] + length
            return f[4][pos:pos+length]
        
    def write(self, fd, data):
        if self.real or (self.realstd and fd in self.std):
            return os.write(fd, bytes(data))
        else:
            if self._needs_copy:
                self.finish_clone()

            f = self.fd_dict[fd]
            f[4] = f[4][:f[0]] + data
            f[0] = f[0] + len(data)
            f[1] = f[0]
            return len(data)

    def content(self, f):
        if type(f) == int:
            return self.fd_dict[f][4]
        else:
            return self.file_dict[f]

    def add(self, file_dict):
        if self._needs_copy:
            self.finish_clone()

        for f in file_dict:
            data = self.convert_data(file_dict[f])
            if f in (STDIN, STDOUT, STDERR):
                self.fd_dict[f][1] += len(data)
                self.fd_dict[f][4] += data
            else:
                self.file_dict[f] = data

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
        clone.fd_dict = self.fd_dict
        clone.file_dict = self.file_dict
        clone._needs_copy = True
        return clone

    def finish_clone(self):
        self.file_dict = self.file_dict.copy()
        fds = self.fd_dict
        self.fd_dict = dict([(fd, fds[fd].copy()) for fd in fds])
        self._needs_copy = False
