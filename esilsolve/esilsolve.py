import z3
from .r2api import R2API
from .esilclasses import * 
from .esilstate import ESILState, ESILStateManager
from .esilops import prepare
from time import time

class ESILSolver:
    """
    Manage and run symbolic execution of a binary using ESIL

    :param filename:     The path to the target binary
    :param debug:        Print every executed instruction and constraint info
    :param trace:        Trace the execution and emulate with r2's ESIL VM
    :param optimize:     Use z3 Optimizer instead of Solver (slow)
    :param lazy:         Use lazy solving, don't evaluate path satisfiability
    :param simple:       Use simple solver, often faster (default is True) 
    :param pcode:        Generate ESIL expressions from PCODE using r2ghidra 
    :param check:        Check memory permissions (default is False)

    >>> esilsolver = ESILSolver("/bin/ls", lazy=True)
    """

    def __init__(self, filename:str = None, **kwargs):
        self.kwargs = kwargs
        self.debug = kwargs.get("debug", False)
        self.trace = kwargs.get("trace", False)
        self.lazy  = kwargs.get("lazy", False)
        self.pcode = kwargs.get("pcode", False)
        self.check_perms = kwargs.get("check", False)

        self.hooks = {}
        self.cond_hooks = []
        self.sims = {}

        self.state_manager = None
        self.pure_symbolic = kwargs.get("sym", False)
        self.optimize = kwargs.get("optimize", False)

        flags = kwargs.get("flags", ["-2"])

        self.filename = filename
        # use r2api which caches some data
        # to increase speed
        if filename == None:
            r2api = R2API(flags=flags)
        else:
            if type(filename) == str:
                r2api = R2API(filename=filename,
                    flags=flags, pcode=self.pcode)
            else:
                r2api = R2API(filename,
                    flags=flags, pcode=self.pcode)

        self.r2api = r2api
        self.r2pipe = r2api.r2p
        self.z3 = z3

        self.did_init_vm = False
        self.info = self.r2api.get_info()
        self.stop = False
        self.runtime = 0
        self.steps = 0
        self.ips = 0

        self.sim_all  = kwargs.get("sim_all", False)
        self.sim_unk  = kwargs.get("sim_unk", False)
        # sims really raise init time for r2frida
        self.sim  = kwargs.get("sim", not self.r2api.frida)
        self.reps = {}
        if self.sim:
            from .esilsim import replacements
            self.reps = replacements
            for rep in self.reps:
                self.register_sim(rep, self.reps[rep])

        # context for hook variables
        # not really necessary yet since its single threaded
        # but we must look to the future
        self.context = {}

        if kwargs.get("init", False):
            self.init_state()

    # initialize the ESIL VM
    def init_vm(self):
        """ Initialize r2 ESIL VM """
        self.r2api.init_vm()
        self.did_init_vm = True

    def run(self, 
            target:Address = None, 
            avoid:List[int] = [], 
            merge:List[int] = []) -> ESILState:

        """
        Run the symbolic execution until target is reached

        The state returned is the first one to reach the target

        :param target:     Address or symbol name to reach
        :param avoid:      List of addresses to avoid
        :param merge:      List of addresses for merge points

        >>> state = esilsolver.run(target=0x00804010, avoid=[0x00804020])
        >>> state.evaluate(state.registers["PC"])
        0x00804010
        """

        if type(target) == str:
            target = self.r2api.get_address(target)

        self.stop = False

        # try to avoid leaving valid context when nothing is set
        if avoid == [] and self.state_manager.avoid == []:
            state = self.state_manager.next()
            avoid = self.default_avoid(state)
            if target in avoid:
                avoid.remove(target)

            self.state_manager.add(state)

        if self.filename != None:
            avoid.append(0) # avoid jmp plt nulls

        self.state_manager.avoid = avoid
        self.state_manager.merge = merge
            
        start = time()
        while not self.stop:
            skip = False
            state = self.state_manager.next()
            if state == None:
                self.runtime = time()-start
                self.ips = self.steps/self.runtime
                return
            elif state.exit != None:
                self.state_manager.exit(state)
                continue

            pc = state.registers["PC"].as_long() 

            state.target = target
            instr = self.r2api.disass(pc)

            if self.debug:
                esil = instr.get("esil", "<no esil>")
                print("%016x: %s ( %s )" % (instr["offset"],
                    instr.get("disasm", "<invalid>").ljust(32), esil))

            found = pc == target
            if found:
                self.terminate()
        
            if pc in self.hooks:
                for hook in self.hooks[pc]:
                    # returning False is a shortcut to skip instr
                    skip = skip or (hook(state) is False)

            for cond_hook in self.cond_hooks:
                if cond_hook(instr):
                    for hook in self.hooks[cond_hook]:
                        skip = skip or (hook(state) is False)

            has_sim = False
            if not found and instr["type"] == "call":
                jmp = instr.get("jump", -1)
                has_sim = jmp in self.sims
                if not has_sim and self.sim_all:
                    if "sym.imp" in instr["disasm"]:
                        skip = True # skip if no sim and sim_all

                elif not has_sim and self.sim_unk:
                    if "sym.unk" in instr["disasm"]:
                        unk_name = instr["disasm"].split(" ")[-1]
                        imp_name = unk_name.replace(".unk.", ".imp.")
                        self.register_sim(jmp, self.reps[imp_name])
                        has_sim = True

            if skip or has_sim:
                if has_sim:
                    self.call_sim(state, instr)

                if state.registers["PC"].as_long() == pc:
                    state.registers["PC"] = pc + instr["size"]

                self.state_manager.add(state)
                continue

            if not self.stop:
                new_states = state.step()
                self.steps += 1
                for new_state in new_states:
                    self.state_manager.add(new_state)
            else:
                self.state_manager.add(state)
                self.runtime = time()-start
                self.ips = self.steps/self.runtime
                return state

    def terminate(self):
        """ End the execution """
        self.stop = True

    def resume(self):
        """ resume the process in r2frida """
        self.r2api.frida_continue()

    # get rets from initial state to stop at
    def default_avoid(self, state: ESILState):
        pc = state.registers["PC"].as_long() 
        func = self.r2api.function_info(pc)
        instrs = self.r2api.disass_function(pc)

        rets = []
        for instr in instrs:
            if instr["type"] == "ret":
                rets.append(instr["offset"])

        return rets

    def register_hook(self, addr: HookTarget, hook: Callable):
        """
        Register a function to be called when specified address is reached

        :param addr:     Address at which the hook will be called
        :param hook:     Function to call when the above address is hit
        """

        if type(addr) == str:
            addr = self.r2api.get_address(addr)
        elif type(addr) != int:
            self.cond_hooks.append(addr)

        if addr in self.hooks:
            self.hooks[addr].append(hook)
        else:
            self.hooks[addr] = [hook]

    def register_sim(self, func: Address, hook: Callable):
        """
        Register a function as a simulated function to improve symex

        :param func:     Name of function or address to replace
        :param hook:     ESILSim to call when the above address is hit
        """

        addr = self.r2api.get_address(func)
        if addr != None:
            self.sims[addr] = hook

    def deregister(self, func: Address):
        """
        Deregister a function as a hook or simulated function

        :param func:     Name of function or address
        """

        addr = self.r2api.get_address(func)
        if addr in self.sims:
            self.sims.pop(addr)
        elif addr in self.hooks:
            self.hooks.pop(addr)

    def call_sim(self, state: ESILState, instr: Dict):
        target = instr["jump"]
        sim = self.sims[target]

        self.r2api.analyze_function(target)

        arg_count = sim.__code__.co_argcount-1
        bits = state.bits

        cc = self.r2api.calling_convention(target)
        args = [state]
        if "args" in cc:
            # register args
            for i in range(arg_count):
                arg = cc["args"][i]
                if arg in state.registers:
                    args.append(prepare(state.registers[arg]))
        else:
            # read from stack
            sp = state.registers["SP"].as_long()
            for i in range(arg_count):
                addr = sp + int(i*bits/8)
                args.append(prepare(state.memory[addr]))

        state.registers[cc["ret"]] = sim(*args)
        # fail contains next instr addr
        state.registers["PC"] = instr["fail"]

    def set_args(self, state, addr, args=[]):
        arg_count = len(args)
        if arg_count == 0:
            return

        self.r2api.analyze_function(addr)
        cc = self.r2api.calling_convention(addr)
        if "args" in cc:
            # register args
            for i in range(arg_count):
                reg = cc["args"][i]
                if reg in state.registers:
                    argv = self.prep_arg(state, args[i])
                    state.registers[reg] = argv
        else:
            # read from stack
            sp = state.registers["SP"].as_long()
            for i in range(arg_count):
                addr = sp + int(i*state.bits/8)
                argv = self.prep_arg(state, args[i])
                state.memory[addr] = argv

    def prep_arg(self, state, arg):
        if type(arg) == int:
            return z3.BitVecVal(arg, state.bits)

        elif type(arg) in (str, bytes):
            addr = state.memory.alloc(len(arg)+1)
            state.memory[addr] = arg
            return z3.BitVecVal(addr, state.bits)

        elif type(arg) == list:
            b = int(state.bits/8)
            size = (len(arg)+1)*b
            addr = state.memory.alloc(size)
            new_addr = addr
            for i in range(len(arg)):
                argv = self.prep_arg(state, arg[i])
                state.memory[new_addr] = argv
                new_addr += int(argv.size()/8)

            state.memory[new_addr] = 0

            return z3.BitVecVal(addr, state.bits)

        else:
            return arg
        
    def call_state(self, addr: Address, args=[]) -> ESILState:
        """
        Create an ESILState with PC at address and the VM initialized

        :param addr:     Name of symbol or address to begin execution
        :param args:     List of arguments to the called function, assigned
                         according to the CC. Inner lists will become ptrs to
                         the contained elements so main's (argc, **argv) can be passed
                         like args=[4, ["hello", "there", "general", "kenobi"]]

        >>> state = esilsolver.call_state("sym.validate")
        """

        if type(addr) == str:
            addr = self.r2api.get_address(addr)

        # seek to function and init vm
        self.r2api.seek(addr)
        self.init_vm()
        state = self.init_state()
        self.set_args(state, addr, args)
        # state.registers["PC"] = addr 

        return state

    def frida_state(self, addr: Address) -> ESILState:
        """
        Create an ESILState with PC at address from r2frida

        :param addr:     Name of symbol or address to begin execution

        >>> state = esilsolver.frida_state("validate")
        """

        if type(addr) == str:
            addr = self.r2api.get_address(addr)

        self.r2api.frida_init(addr)
        return self.init_state()

    def debug_state(self, addr: Address) -> ESILState:
        """
        Create an ESILState with PC at address from debugger bp

        :param addr:     Name of symbol or address to begin execution

        >>> state = esilsolver.debug_state("validate")
        """

        if type(addr) == str:
            addr = self.r2api.get_address(addr)

        self.r2api.debug_init(addr)
        return self.init_state()

    def reset(self, state: ESILState = None):
        """ 
        Reset the StateManager with just the provided state 
        
        :param state: The state that will become the only active state
        """

        self.state_manager = ESILStateManager([], lazy=self.lazy)
        
        if state == None:
            state = self.state_manager.entry_state(self.r2api, **self.kwargs)
        else:
            self.state_manager.add(state)

    def init_state(self) -> ESILState:
        """ Create an ESILState without using the existing ESIL VM """

        self.state_manager = ESILStateManager([], lazy=self.lazy)
        state = self.state_manager.entry_state(self.r2api, **self.kwargs)
        return state

    # this is confusing since I call a method entry_state in ESILSM
    def entry_state(self, argv=[], env=[]) -> ESILState:
        """ Create an ESILState at the entrypoint of the binary"""

        self.r2api.seek("entry0")
        instrs = self.r2api.disass_function("entry0")
        start_main = self.r2api.get_address("reloc.__libc_start_main")

        def __libc_start_main(state):
            main_addr = state.r2api.get_address("main")
            self.set_args(state, main_addr, [len(argv), argv, env])
            state.registers["PC"] = main_addr
            return False

        def halt(state):
            cc = state.r2api.calling_convention("main")
            state.exit = state.registers[cc.get("ret", "A0")]
            return False

        if start_main not in (0, None):
            self.register_hook(start_main, __libc_start_main)
            if instrs[-1]["type"] != "call":
                self.register_hook(instrs[-1]["offset"], halt)

        return self.init_state()

    def blank_state(self, addr: Address = 0) -> ESILState:
        """
        Create an ESILState with everything (except PC) symbolic

        :param addr:     Name of function or address to begin execution
        """

        addr = self.r2api.get_address(addr)

        self.state_manager = ESILStateManager([], lazy=self.lazy)
        kwargs = self.kwargs.copy()
        kwargs["sym"] = True
        state = self.state_manager.entry_state(self.r2api, **kwargs)
        pc_size = state.registers["PC"].size()
        state.registers["PC"] = z3.BitVecVal(addr, pc_size)
        return state

