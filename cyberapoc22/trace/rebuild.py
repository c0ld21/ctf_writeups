import angr, claripy

input_len = 0x20

p = angr.Project('rebuilding')
binary = './rebuilding'
argv = claripy.BVS('argv', 8 * input_len)
state = p.factory.entry_state(args=[binary, argv])

for x in range(input_len):
    state.solver.add(argv.get_byte(x) >= 33)
    state.solver.add(argv.get_byte(x) <= 126)

sim = p.factory.simulation_manager(state)
sim.explore(find=lambda s: b'The password is correct' in s.posix.dumps(1))


import sys
if len(sim.found) > 0:
    s = sim.found[0]
    print("argv[1] = {!r}".format(s.solver.eval(argv, cast_to=bytes)))
    print(s.posix.dumps(sys.stdin.fileno()).decode())
    print(s.posix.dumps(sys.stdout.fileno()).decode())

# HTB{h1d1ng_1n_c0nstruct0r5_1n1t}
