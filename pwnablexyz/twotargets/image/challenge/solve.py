from z3 import *

x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,x29,x30,x31 = BitVecs("x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x22 x23 x24 x25 x26 x27 x28 x29 x30 x31",8)

x = Solver()

x.add((ord(b'\x55') ^ ((x0  + 0) << 4 | (x0 + 0) >> 4)) == ord(b'\x11'))
x.add((ord(b'\x48') ^ ((x1  + 1) << 4 | (x1 + 1) >> 4)) == ord(b'\xde'))
x.add((ord(b'\x89') ^ ((x2  + 2) << 4 | (x2 + 2) >> 4)) == ord(b'\xcf'))
x.add((ord(b'\xe5') ^ ((x3  + 3) << 4 | (x3 + 3) >> 4)) == ord(b'\x10'))
x.add((ord(b'\x48') ^ ((x4  + 4) << 4 | (x4 + 4) >> 4)) == ord(b'\xdf'))
x.add((ord(b'\x83') ^ ((x5  + 5) << 4 | (x5 + 5) >> 4)) == ord(b'\x75'))
x.add((ord(b'\xec') ^ ((x6  + 6) << 4 | (x6 + 6) >> 4)) == ord(b'\xbb'))
x.add((ord(b'\x50') ^ ((x7  + 7) << 4 | (x7 + 7) >> 4)) == ord(b'\xa5'))

x.add((ord(b'\x64') ^ ((x8  + 8) << 4 | (x8 + 8) >> 4)) == ord(b'\x43'))
x.add((ord(b'\x48') ^ ((x9  + 9) << 4 | (x9 + 9) >> 4)) == ord(b'\x1e'))
x.add((ord(b'\x8b') ^ ((x10 + 10) << 4 | (x10 + 10) >> 4)) == ord(b'\x9d'))
x.add((ord(b'\x04') ^ ((x11 + 11) << 4 | (x11 + 11) >> 4)) == ord(b'\xc2'))
x.add((ord(b'\x25') ^ ((x12 + 12) << 4 | (x12 + 12) >> 4)) == ord(b'\xe3'))
x.add((ord(b'\x28') ^ ((x13 + 13) << 4 | (x13 + 13) >> 4)) == ord(b'\xbf'))
x.add((ord(b'\x00') ^ ((x14 + 14) << 4 | (x14 + 14) >> 4)) == ord(b'\xf5'))
x.add((ord(b'\x00') ^ ((x15 + 15) << 4 | (x15 + 15) >> 4)) == ord(b'\xd6'))

x.add((ord(b'\x00') ^ ((x16 + 16) << 4 | (x16 + 16) >> 4)) == ord(b'\x96'))
x.add((ord(b'\x48') ^ ((x17 + 17) << 4 | (x17 + 17) >> 4)) == ord(b'\x7f'))
x.add((ord(b'\x89') ^ ((x18 + 18) << 4 | (x18 + 18) >> 4)) == ord(b'\xbe'))
x.add((ord(b'\x45') ^ ((x19 + 19) << 4 | (x19 + 19) >> 4)) == ord(b'\xb0'))
x.add((ord(b'\xf8') ^ ((x20 + 20) << 4 | (x20 + 20) >> 4)) == ord(b'\xbf'))
x.add((ord(b'\x31') ^ ((x21 + 21) << 4 | (x21 + 21) >> 4)) == ord(b'\xb7'))
x.add((ord(b'\xc0') ^ ((x22 + 22) << 4 | (x22 + 22) >> 4)) == ord(b'\x96'))
x.add((ord(b'\xe8') ^ ((x23 + 23) << 4 | (x23 + 23) >> 4)) == ord(b'\x1d'))

# x.add((ord(b'\x24') ^ ((x24 + 24) << 4 | (x24 + 24) >> 4)) == ord(b'\xa8'))
x.add((ord(b'\xfe') ^ ((x25 + 25) << 4 | (x25 + 25) >> 4)) == ord(b'\xbb'))
x.add((ord(b'\xff') ^ ((x26 + 26) << 4 | (x26 + 26) >> 4)) == ord(b'\x0a'))
x.add((ord(b'\xff') ^ ((x27 + 27) << 4 | (x27 + 27) >> 4)) == ord(b'\xd9'))
x.add((ord(b'\x48') ^ ((x28 + 28) << 4 | (x28 + 28) >> 4)) == ord(b'\xbf'))
x.add((ord(b'\x8d') ^ ((x29 + 29) << 4 | (x29 + 29) >> 4)) == ord(b'\xc9'))
# x.add((ord(b'\x45') ^ ((x30 + 30) << 4 | (x30 + 30) >> 4)) == ord(b'\x0d'))
# x.add((ord(b'\xc0') ^ ((x31 + 31) << 4 | (x31 + 31) >> 4)) == ord(b'\xff'))

print(x.check())
x.model()

l=[x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23] 
flag = ''.join([chr(int(str(x.model()[i]))) for i in l ]) 
print(flag)