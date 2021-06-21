#!/usr/bin/env python3
from base64 import b64decode
from collections import Counter


# chop message into blocks of size `size`
def chop(m: bytes, bs: int = 16) -> list[bytes]:
    return [m[i:i + bs] for i in range(0, len(m), bs)]


# returns True if ECB is likely used
def detect_ecb(c: bytes) -> bool:
    freq = Counter(chop(c))
    # if there are any repeating blocks then return true
    return True if max(freq.values()) > 1 else False


with open('data/8.txt', 'r') as f:
    cs = [bytes.fromhex(c) for c in filter(None, f.read().split('\n'))]

for c in cs:
    if detect_ecb(c):
        print('ECB mode found:', c)
        break
