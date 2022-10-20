#!/usr/bin/env python3
from mycrypto import score

c = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'


# c = bytes
# k = num
def xor(c, k):
    m = bytearray()
    for i in c:
        m.append(i ^ k)
    return m


# (c, k, m, s)
def solve_simple_xor(c: bytes, log_best=True) -> tuple:
    res = (c, '', '', float('inf'))
    for k in range(128):
        try:
            m = xor(c, k)
            s = score(m)
            if s < res[3]:
                if log_best:
                    print(k, '/', s, '/', m)
                res = (c, chr(k), m, s)
        except Exception:
            pass
    return res


print(solve_simple_xor(bytes.fromhex(c), log_best=False)[2].decode('ascii'))
