import r2lang
import esilsolve
import r2pipe
import solver 

class ESILSolvePlugin:

    def __init__(self):
        self.commands = {
            "aesxi": self.handleInit,
            "aesxs": self.handleSym,
            "aesxc": self.handleConstrain,
            "aesxr": self.handleRun,
            #"aesxm": self.handleModel,
            "aesxe": self.handleEval,
            "aesxd": self.handleDump
        }

        self.symbols = {}
        self.esinstance = None
        self.initialized = False
        self.currentState = None

    def command(self, args):
        cmd = args[0]
        self.commands[cmd](args)

    def handleInit(self, args):
        self.r2p = r2pipe.open()
        self.r2p.cmd("aei; aeim")
        self.esinstance = esilsolve.ESILSolver(self.r2p)
        self.initialized = True

    def handleSym(self, args):
        if not self.initialized:
            print("error: need to initialize first")
            return

        s = 0
        if len(args) > 2:
            s = int(args[2])

        reg = args[1]

        state = self.esinstance.states[s]
        state.setSymbolicRegister(reg)

        self.symbols[reg] = state.registers[reg]

    def handleConstrain(self, args):
        if not self.initialized:
            print("error: need to initialize first")
            return

        s = 0
        if len(args) > 3:
            s = int(args[3])
        state = self.esinstance.states[s]

        reg = args[1]

        if args[2] == "min": 
            state.solver.minimize(state.registers[reg])
        elif args[2] == "max":
            state.solver.maximize(state.registers[reg])
        else:
            val = toInt(args[2])
            state.constrainRegister(reg, val)

    def handleRun(self, args):
        if not self.initialized:
            print("error: need to initialize first")
            return

        s = 0
        if len(args) > 2:
            s = int(args[2])

        target = toInt(args[1])

        state = self.esinstance.states[s]
        self.esinstance.run(state, target=target)

    def handleEval(self, args):
        if not self.initialized:
            print("error: need to initialize first")
            return

        s = 0
        if len(args) > 2:
            s = int(args[2])

        reg = args[1]

        state = self.esinstance.states[s]
        register = self.symbols[reg]
        sat = state.solver.check()

        if sat != solver.sat:
            print("error: not sat")
            return

        model = state.solver.model()
        v = model.eval(register)

        print("%s: %s" % (reg, v))

    def handleDump(self, args):
        print("registers:")
        s = 0
        if len(args) > 1:
            s = int(args[1])

        state = self.esinstance.states[s]

        if len(args) > 2:
            regname = args[2]
            reg = state.registers._registers[regname]
            print("%s: %s" % (reg["name"], reg["bv"]))
            return

        for regname in state.registers._registers:
            reg = state.registers._registers[regname]
            if reg["parent"] == None:
                print("%s: %s" % (reg["name"], reg["bv"]))

def toInt(v):
    if len(v) > 2 and v[:2] == "0x":
        return int(v, 16)
    
    return int(v)

def esplugin(a):

    def _call(s):
        #print(s)
        args = s.split(" ")
        if args[0] in es.commands:
            try:
                es.command(args)
            except Exception as e:
                print(e)
            return 1

        return 0

    return {
        "name": "ESILSolve",
        "license": "GPL",
        "desc": "plugin for esil-based symbolic execution",
        "call": _call,
    }
es = ESILSolvePlugin()
#print("Registering ESILSolve plugin...")
r2lang.plugin("core", esplugin)