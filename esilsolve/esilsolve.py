import z3
from .r2api import R2API
from .esilclasses import * 
from .esilstate import ESILState, ESILStateManager
from .esilsim import ESILSim

z3.set_param('rewriter.hi_fp_unspecified', 'true')

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

        self.states = []
        self.hooks = {}
        self.sims = {}
        self.state_manager = None
        self.pure_symbolic = kwargs.get("sym", False)

        self.conditionals = {}
        self.cond_count = 0
        self.optimize = kwargs.get("optimize", False)

        flags = kwargs.get("flags", ["-2"])

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
            merge:List[int] = [],
            make_calls=True) -> ESILState:

        """
        Run the symbolic execution until target is reached

        The state returned is the first one to reach the target

        :param target:     Address or symbol name to reach
        :param avoid:      List of addresses to avoid
        :param merge:      List of addresses for merge points
        :param make_calls: Do not step over function calls

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

            # no target or hooks, target is last ret
            if target == None and avoid != []:
                if len(self.hooks) == 0:
                    target = avoid[-1]
                    avoid = avoid[:-1]
            
            if target in avoid:
                avoid.remove(target)

            self.state_manager.add(state)

        self.state_manager.avoid = avoid
        self.state_manager.merge = merge

        if type(target) == str:
            target = self.r2api.get_address(target)
            
        while not self.stop:
            state = self.state_manager.next()
            if state == None:
                return

            pc = state.registers["PC"].as_long() 

            state.target = target
            instr = self.r2api.disass(pc)
            found = pc == target
            if found:
                self.terminate()
        
            if pc in self.hooks:
                for hook in self.hooks[pc]:
                    hook(state)

            if instr["type"] == "call":
                if not make_calls:
                    state.registers["PC"] = pc + instr["size"]
                    self.state_manager.add(state)
                    continue

                elif instr["jump"] in self.sims:
                    self.call_sim(state, instr)

            if not self.stop:
                new_states = state.step()
                for new_state in new_states:
                    self.state_manager.add(new_state)
            else:
                self.state_manager.add(state)
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

    def register_hook(self, addr: Address, hook: Callable):
        """
        Register a function to be called when specified address is reached

        :param addr:     Address at which the hook will be called
        :param hook:     Function to call when the above address is hit
        """

        if type(addr) == str:
            addr = self.r2api.get_address(addr)

        if addr in self.hooks:
            self.hooks[addr].append(hook)
        else:
            self.hooks[addr] = [hook]

    def register_sim(self, func: Address, hook: ESILSim):
        """
        Register a function as a simulated function to improve symex

        :param func:     Name of function or address to replace
        :param hook:     ESILSim to call when the above address is hit
        """

        addr = self.r2api.get_address(func)
        self.r2api.analyze_function(func)
        self.sims[addr] = hook

    def call_sim(self, state: ESILState, instr: Dict):
        target = instr["jump"]
        sim = self.sims[target](state)
        arg_count = sim.arg_count()
        bits = state.bits

        cc = self.r2api.calling_convention(target)
        args = []
        if "args" in cc:
            # register args
            for i in range(arg_count):
                arg = cc["args"][i]
                if arg in state.registers:
                    args.append(state.registers[arg])
        else:
            # read from stack
            sp = state.registers["SP"].as_long()
            for i in range(arg_count):
                addr = sp + int(i*bits/8)
                args.append(state.memory[addr])


        state.registers[cc["ret"]] = sim(*args)
        # fail contains next instr addr
        state.registers["PC"] = instr["fail"]
        
    def call_state(self, addr: Address) -> ESILState:
        """
        Create an ESILState with PC at address and the VM initialized

        :param addr:     Name of symbol or address to begin execution

        >>> state = esilsolver.call_state("sym.validate")

        """

        if type(addr) == str:
            addr = self.r2api.get_address(addr)

        # seek to function and init vm
        self.r2api.seek(addr)
        self.init_vm()
        state = self.init_state()
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
        state = self.init_state()

        return state

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

