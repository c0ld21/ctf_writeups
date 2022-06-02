
enc = b'akf`|cncX~hrXlihpXFUJXoftXhwsnhifkXenst8XEnimfXcncz'
arrows = 0x17
pots = 0xb
i = 0

while pots <= 255:
    while i <= 0x32:
        r2 = enc[i] ^ arrows
        r3 = r2 ^ pots
        print(chr(r3), end='')
        i += 1
    print('----')
    i = 0
    pots += 1

#flag{did_you_know_ARM_has_optional_bits?_Binja_did}
