import binascii

with open("packets.txt","r") as f:
    txt = f.read()

packets = txt.split('\n\n')

def strnums2bytes(nums):
    return [int(x, base=16) for x in nums.split(' ')]

def bytes2pckt(text):
    p = []
    for l in text.splitlines():
        parts = l.split('  ')
        if parts[0] in ["0000", "0010"]:
            continue
        if parts[0] == "0020":
            p += strnums2bytes(parts[1][6:])
        else:
            p += strnums2bytes(parts[1])
    p[6] = 17
    return bytes(p)

i = 0
for p in packets:
    final = bytes2pckt(p)

    with open("ipv6_{}".format(i), "wb") as out:
        print(binascii.hexlify(final))
        out.write(final)
        i += 1
