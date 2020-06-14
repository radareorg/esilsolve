import r2lang
import esilsolve
import r2pipe
import z3
import json
import shlex
import colorama

class ESILSolvePlugin:

    def __init__(self, r2p):
        self.r2p = r2p
        
        self.commands = {
            # aesx - Analysis: Emulation / Symbolic eXecution
            "aesx?": self.print_help,
            "aesxi": self.handle_init,
            "aesxs": self.handle_set_symbolic,
            "aesxv": self.handle_set_value,
            "aesxc": self.handle_constrain,
            "aesxx": self.handle_execute_constrain,
            "aesxxc": self.handle_execute_constrain,
            "aesxxe": self.handle_execute_constrain,
            "aesxr": self.handle_run,
            "aesxra": self.handle_run,
            "aesxe": self.handle_eval,
            "aesxej": self.handle_eval,
            "aesxb": self.handle_eval_buffer,
            "aesxbj": self.handle_eval_buffer,
            "aesxd": self.handle_dump,
            "aesxdj": self.handle_dump,
            "aesxa": self.handle_apply
        }

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
                self.print("| %s%s%-30s%s%s" % (
                    line[0], 
                    colorama.Fore.YELLOW, line[1], colorama.Style.RESET_ALL, 
                    line[2]
                ))

        usage = ["Usage: aesx[iscxrebda]", "", "# Core plugin for ESILSolve"]

        lines = [
            usage,
            ["aesxi", " [debug]", "Initialize the ESILSolve instance and VM"],
            ["aesxs", " reg|addr [name] [length]", "Set symbolic value in register or memory"],
            ["aesxv", " reg|addr value", "Set concrete value in register or memory"],
            ["aesxc", " sym value", "Constrain symbol to be value, min, max, regex"],
            ["aesxx", "[ec] expr value", "Execute ESIL expression and evaluate/constrain the result"],
            ["aesxr", "[a] target [avoid x,y,z]", "Run symbolic execution until target address, avoiding x,y,z"],
            ["aesxe", "[j] sym1 [sym2] [...]", "Evaluate symbol in current state"],
            ["aesxb", "[j] sym1 [sym2] [...]", "Evaluate buffer in current state"],
            ["aesxd", "[j] [reg1] [reg2] [...]", "Dump register values / ASTs"],
            ["aesxa", "", "Apply the current state, setting registers and memory"]
        ]

        print_help_lines(lines)

    def handle_init(self, args):
        debug = False
        if len(args) > 1 and args[1] == "debug":
            debug = True

        self.esinstance = esilsolve.ESILSolver(self.r2p, debug=debug)
        core = self.r2p.cmdj("ij")["core"]
        if "referer" not in core and "frida:" != core["file"][:7]:
            self.esinstance.r2api.init_vm()

        self.state = self.esinstance.init_state()
        self.initialized = True
        self.symbols = {}

    def handle_apply(self, args):
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        # constrain these first so the user gets the "expected" result
        for sym in self.symbols:
            value = self.state.evalcon(self.symbols[sym])

        self.state.apply()

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
        self.symbols[name] = sym

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

    def handle_eval(self, args):
        is_json = args[0][-1] == "j"
        if not self.initialized:
            self.print("error: need to initialize first")
            return

        js = {}
        self.state.solver.push()
        for arg in args[1:]:
            sym = self.get_symbol(arg)
            val = self.state.evaluate(sym)
            self.state.solver.add(sym == val)

            if not is_json:
                self.print("%s: %d" % (arg, val.as_long()))
            else:
                js[arg] = val.as_long()

        if is_json:
            self.print(json.dumps(js))

        self.state.solver.pop()

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
            return self.symbols[arg]
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


r2p = r2pipe.open()
es = ESILSolvePlugin(r2p)
#r2print(r2p, " -- registering ESILSolve plugin... enter %saesx?%s for help" % \
#    (colorama.Fore.YELLOW, colorama.Style.RESET_ALL))
r2lang.plugin("core", esplugin)