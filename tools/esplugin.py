

try:
    import r2lang
    r2p = None

    import os, sys
    import esilsolve
    import r2pipe
    import z3
    import json
    import shlex
    import colorama

    r2p = r2pipe.open()
except ImportError as e:
    #print("esplugin could not be loaded: " + str(e))
    pass

add_shortcuts = True

class ESILSolvePlugin:

    def __init__(self, r2p):
        self.r2p = r2p
        
        self.commands = {
            # aesx - Analysis: Emulation / Symbolic eXecution
            "aesx?" : self.print_help,
            "aesxi" : self.handle_init,
            "aesxif": self.handle_init,
            "aesxfc": self.handle_continue,
            "aesxs" : self.handle_set_symbolic,
            "aesxsb": self.handle_set_symbolic,
            "aesxsc": self.handle_set_symbolic,
            "aesxv" : self.handle_set_value,
            "aesxc" : self.handle_constrain,
            "aesxc+": self.handle_push,
            "aesxc-": self.handle_pop,
            "aesxx" : self.handle_execute_constrain,
            "aesxxc": self.handle_execute_constrain,
            "aesxxe": self.handle_execute_constrain,
            "aesxr" : self.handle_run,
            "aesxra": self.handle_run,
            "aesxrc": self.handle_run,
            "aesxe" : self.handle_eval,
            "aesxej": self.handle_eval,
            "aesxb" : self.handle_eval_buffer,
            "aesxbj": self.handle_eval_buffer,
            "aesxd" : self.handle_dump,
            "aesxdj": self.handle_dump,
            "aesxa" : self.handle_apply,
            "aesxwl": self.handle_state_list,
            "aesxws": self.handle_state_set
        }

        if add_shortcuts:
            new = {}
            for c in self.commands: 
                new["X"+c[4:]] = self.commands[c]

            self.commands.update(new)

        self.symbols = {}
        self.esinstance = None
        self.initialized = False
        self.state = None

    def command(self, args):
        cmd = args[0]
        self.commands[cmd](args)

    def print_help(self, args):

        def print_help_lines(line):
            usage = lines[0]
            self.print("%s%s%s %s%s" % \
                (colorama.Fore.YELLOW, usage[0], usage[1], usage[2], colorama.Style.RESET_ALL))
            for line in lines[1:]:
                self.print("| %s%s%-40s%s%s" % (
                    line[0], 
                    colorama.Fore.YELLOW, line[1], colorama.Style.RESET_ALL, 
                    line[2]
                ))

        usage = ["Usage: aesx[iscxrebdaw]", "", "# Core plugin for ESILSolve"]

        lines = [
            usage,
            ["aesxi", "[f] [debug] [lazy] [check]", "Initialize the ESILSolve instance and VM"],
            ["aesxs", "[bc] reg|addr [name] [length]", "Set symbolic value in register or memory"],
            ["aesxv", " reg|addr value", "Set concrete value in register or memory"],
            ["aesxc", " sym value", "Constrain symbol to be value, min, max, regex"],
            ["aesxc", "[+-]", "Push / pop the constraint context"],
            ["aesxx", "[ec] expr value", "Execute ESIL expression and evaluate/constrain the result"],
            ["aesxr", "[ac] target [avoid x,y,z]", "Run symbolic execution until target address, avoiding x,y,z"],
            ["aesxf", "[c]", "Resume r2frida after symex is finished"],
            ["aesxe", "[j] sym1 [sym2] [...]", "Evaluate symbol in current state"],
            ["aesxb", "[j] sym1 [sym2] [...]", "Evaluate buffer in current state"],
            ["aesxd", "[j] [reg1] [reg2] [...]", "Dump register values / ASTs"],
            ["aesxa", "", "Apply the current state, setting registers and memory"],
            ["aesxw", "[ls] [state number]", "List or set the current states"]
        ]

        print_help_lines(lines)

    def handle_init(self, args):
        debug = "debug" in args
        lazy = "lazy" in args
        check = "check" in args

        self.esinstance = esilsolve.ESILSolver(
            self.r2p, debug=debug, lazy=lazy, check=check)

        if args[0][-1] != "f":
            thread = None
            if len(args) > 1 and is_int(args[1]):
                thread = to_int(args[1])

            self.esinstance.r2api.init_vm(thread)
            self.state = self.esinstance.init_state()

        else:
            pc = to_int(self.r2p.cmd("s"))
            self.state = self.esinstance.frida_state(pc)

        self.initialized = True
        self.symbols = {}

    def handle_continue(self, args):
        self.esinstance.resume()

    def handle_apply(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        # constrain these first so the user gets the "expected" result
        for sym in self.symbols:
            value = self.state.evalcon(self.symbols[sym]["value"])

        self.state.apply()

    def handle_state_list(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return


        prefix = "active:   "
        for i, state in enumerate(self.esinstance.state_manager.active):
            self.print("%s[%03d] addr: %016x steps: %06d" % (
                prefix, i, state.registers["PC"].as_long(), state.steps
            ))
            prefix = " "*10

        prefix = "\ninactive: "
        for i, state in enumerate(self.esinstance.state_manager.inactive):
            self.print("%s[%03d] addr: %016x steps: %06d" % (
                prefix, i, state.registers["PC"].as_long(), state.steps
            ))
            prefix = " "*10

        prefix = "\nunsat:    "
        for i, state in enumerate(self.esinstance.state_manager.unsat):
            self.print("%s[%03d] addr: %016x steps: %06d" % (
                prefix, i, state.registers["PC"].as_long(), state.steps
            ))
            prefix = " "*10

    def handle_state_set(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        state_num = to_int(args[1])
        self.state = self.esinstance.state_manager.active[state_num]

    def handle_set_symbolic(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        set_val = args[1]

        length = 8
        name = "%s" % set_val
        if len(args) > 2 and not is_int(args[2]):
            name = args[2]

        elif len(args) > 2 and is_int(args[2]):
            length = to_int(args[2])

        if len(args) > 3:
            length = to_int(args[3])


        sym = z3.BitVec(name, length*8)

        sym_type = "int"
        if args[0][-1] == "b":
            sym_type = "bytes"
        elif args[0][-1] == "c":
            sym_type = "str" # c string

        self.symbols[name] = {"value": sym, "type": sym_type}

        # set register
        if not is_int(set_val):
            if set_val in self.state.registers:
                self.state.registers[set_val] = sym
        # set memory
        else:
            self.state.memory[to_int(set_val)] = sym

    def handle_set_value(self, args):
        if not self.initialized:
            # idk
            self.r2p.cmd("aer %s=%s" % (args[1], args[2]))
            return

        set_val = args[1]
        val = args[2]

        if is_int(val):
            val = to_int(val)

        # set register
        if not is_int(set_val):
            if set_val in self.state.registers:
                self.state.registers[set_val] = val

        # set memory
        else:
            self.state.memory[to_int(set_val)] = val

    def handle_constrain(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        sym = self.get_symbol(args[1])
        con = args[2]

        if con == "min": 
            self.state.solver.minimize(sym)
        elif con == "max":
            self.state.solver.maximize(sym)
        elif is_int(con):
            val = to_int(con)
            self.state.constrain(sym == val)
        else:
            self.state.constrain_bytes(sym, con)

    def handle_push(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        self.state.solver.push()

    def handle_pop(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        self.state.solver.pop()

    def handle_execute_constrain(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        expr = args[1]
        self.state.proc.parse_expression(expr, self.state)

        if args[0][-1] == "c":
            sym, = esilsolve.pop_values(self.state.stack, 1)

            con = args[2]
            if con == "min": 
                self.state.solver.minimize(sym)
            elif con == "max":
                self.state.solver.maximize(sym)
            elif is_int(con):
                val = to_int(con)
                self.state.constrain(sym == val)
            else:
                self.state.constrain_bytes(sym, con)

        elif args[0][-1] == "e":
            sym, = esilsolve.pop_values(self.state.stack, 1)

            val = self.state.evaluate(sym)
            self.state.constrain(sym == val)
            self.print(val.as_long())

    def handle_run(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        target = to_int(args[1])
        avoid = []
        if len(args) > 2:
            avoid = [to_int(x) for x in args[2].split(",")]

        self.state = self.esinstance.run(target=target, avoid=avoid)

        if args[0][-1] == "a":
            self.handle_apply(args)
        elif args[0][-1] == "c":

            state_mgr = self.esinstance.state_manager

            state_dict = {
                "active": [state_mgr.active, colorama.Fore.LIGHTGREEN_EX],
                "inactive": [state_mgr.inactive, colorama.Fore.LIGHTRED_EX],
                "unsat": [state_mgr.unsat, colorama.Fore.RED]
            }

            pcs = {}
            for state_type in state_dict:
                for state in state_dict[state_type][0]:
                    pc = state.registers["PC"].as_long()
                    comment = "%s: " % state_type

                    if pc == target:
                        comment = "target: " 
                    
                    if pc not in pcs:
                        pcs[pc] = True
                        state.solver.push()
                        sym_cmts = []
                        for sym_name in self.symbols:
                            sym = self.symbols[sym_name]["value"]
                            sym_type = self.symbols[sym_name]["type"]
                            sym_val = "0x%08x" % state.evalcon(sym).as_long()

                            if sym_type == "bytes":
                                sym_val = state.evaluate_buffer(sym)
                            elif sym_type == "str":
                                sym_val = state.evaluate_string(sym)

                            sym_cmts.append("%s = %s" % (
                                sym_name,
                                sym_val))

                        state.solver.pop()
                        comment += ", ".join(sym_cmts)
                        self.r2p.cmd("CC %s @ %d" % (comment, pc))

    def handle_eval(self, args):
        is_json = args[0][-1] == "j"
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        js = {}
        #self.state.solver.push()
        for arg in args[1:]:
            sym = self.get_symbol(arg)
            val = self.state.evaluate(sym).as_long()
            self.state.solver.add(sym == val)

            if arg in self.symbols:
                if self.symbols[arg]["type"] == "bytes":
                    val = self.state.evaluate_buffer(sym)
                elif self.symbols[arg]["type"] == "str":
                    val = self.state.evaluate_string(sym)

            if not is_json:
                self.print("%s: %s" % (arg, str(val)))
            else:
                js[arg] = val

        if is_json:
            self.print(json.dumps(js))

        #self.state.solver.pop()

    def handle_eval_buffer(self, args):
        is_json = args[0][-1] == "j"
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        js = {}
        for arg in args[1:]:
            sym = self.get_symbol(arg)
            v = self.state.evaluate_buffer(sym)

            if not is_json:
                self.print("%s: %s" % (arg, str(v)))
            else:
                js[arg] = list(v)

        if is_json:
            self.print(json.dumps(js))

    def handle_dump(self, args):
        is_json = args[0][-1] == "j"

        state = self.state
        js = {}
        if len(args) > 1:
            regname = args[1]
            reg = state.registers._registers[regname]
            if not is_json:
                self.print("%s: %s" % (reg["name"], state.registers[regname]))
            else:
                js[reg["name"]] = str(state.registers[regname])
                self.print(json.dumps(js))

            return

        for regname in state.registers._registers:
            reg = state.registers._registers[regname]
            if not reg["sub"]:
                if not is_json:
                    self.print("%s: %s" % (reg["name"], state.registers[regname]))
                else:
                    js[reg["name"]] = str(state.registers[regname])

        if is_json:
            self.print(json.dumps(js))

    def get_symbol(self, arg):
        if arg in self.symbols:
            return self.symbols[arg]["value"]
        elif arg in self.state.registers:
            return self.state.registers[arg]
        elif is_int(arg):
            return self.state.memory[to_int(arg)]

    def print(self, msg):
        r2print(self.r2p, msg)

def to_int(s):
    if s[:2] == "0x":
        return int(s, 16)

    return int(s)

def is_int(s):
    if s[:1] == "-":
        s = s[1:]

    if s.isdigit() or s[:2] == "0x":
        return True

    return False

def r2print(r2p, msg):
    #r2p._cmd_rlang("?e %s\n" % msg)
    #r2lang.cmd("?e %s" % msg)
    #r2p._cmd_pipe("?e %s" % msg)
    print(msg)

def esplugin(a):

    def _call(s):
        #print(s)
        args = shlex.split(s)
        if args[0] in es.commands:
            try:
                es.command(args)
            except Exception as e:
                print("error: %s" % str(e))

            return 1

        return 0

    return {
        "name": "ESILSolve",
        "license": "GPL",
        "desc": "plugin for esil-based symbolic execution",
        "call": _call,
    }

es = ESILSolvePlugin(r2p)
#r2print(r2p, " -- registering ESILSolve plugin... enter %saesx?%s for help" % \
#    (colorama.Fore.YELLOW, colorama.Style.RESET_ALL))
r2lang.plugin("core", esplugin)