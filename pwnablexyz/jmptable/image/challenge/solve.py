
start = 0xfffffffffff00000
res = 0
while res != 0x10000000000400e38:
    res = (start*8) 
    res = '0x'+hex(res)[3:]
    res = int(res, 16) + 0x006020c0
    if res == 0x10000000000400e38:
        print('Found: ', hex(res))
        print('start: ', hex(start))
        break
    print('Trying: ', hex(res))
    start += 1

print(start)
