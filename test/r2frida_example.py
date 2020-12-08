from esilsolve import ESILSolver
import z3

# start the ESILSolver instance by attaching r2frida 
esilsolver = ESILSolver("frida://usb/attach//iOSCrackMe")

validate = esilsolver.r2api.get_address("validate")
# initialize state with context from hook, app is suspended
state = esilsolver.frida_state(validate)

# initialize symbolic bytes of solution
# and constrain them to be /[a-zA-Z]/
code = z3.BitVec("code", 16*8)
state.constrain_bytes(code, "[a-zA-Z]")
addr = state.registers["A0"].as_long()
state.memory[addr] = code

state = esilsolver.run(validate+0x210, avoid=[validate+0x218])
solution = state.evaluate_buffer(code)
print("CODE: '%s'" % solution.decode())

# write solution into proper place
# esilsolver.r2api.write(addr, solution) 
esilsolver.resume() # resume suspended app
