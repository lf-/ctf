from z3 import *
from itertools import combinations
import codecs

# https://gist.github.com/percontation/11310679

def z3crc32(data, crc=0):
    crc ^= 0xFFFFFFFF
    for c in data:
        for block in range(24, -1, -8):
            crc ^= LShR(c, block) & 0xFF
            for i in range(8):
                crc = If(crc & 1 == BitVecVal(1, 32),
                         LShR(crc, 1) ^ 0xedb88320, LShR(crc, 1))
    return crc ^ 0xFFFFFFFF


s = Solver()
data = [BitVec('data', 32)]  # The "string", actually 5 32-bit buffers


# Returns a z3 expression that is true iff the input BitVec32 as a 4-byte string is all ascii.
def isAscii(bv):
    # Note the use of z3.And here. Using python's `and` would be incorrect!
    return And(32 <= (LShR(bv, 0) & 0xff), (LShR(bv, 0) & 0xff) < 127, 32
               <= (LShR(bv, 8) & 0xff), (LShR(bv, 8) & 0xff) < 127, 32
               <= (LShR(bv, 16) & 0xff), (LShR(bv, 16) & 0xff) < 127, 32
               <= (LShR(bv, 24) & 0xff), (LShR(bv, 24) & 0xff) < 127)


for d in data:
    s.add(isAscii(d))

crc = z3crc32(data)
revd = '3629437067'
subs = [int(revd[x:y]) for x, y in combinations(range(len(revd) + 1), r = 2)]
s.add(Or(*[crc == s for s in subs]))

print(s.check())
m = s.model()
print(m)

def intToText(x):
    return str(codecs.decode(hex(x)[2:].strip('L').ljust(8,'0'), 'hex'))

s = ''
for d in data:
    s += intToText(m.eval(d).as_long())

print(s)

