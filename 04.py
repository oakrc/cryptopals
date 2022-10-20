#!/usr/bin/env python3
from base64 import b64decode
from collections import Counter

from mycrypto import score, solve_simple_xor

with open('data/04.txt', 'r') as f:
    ciphers = [bytes.fromhex(c) for c in f.read().split('\n')]

best = ('', '', b'', float('inf'))
for c in ciphers:
    current = solve_simple_xor(c)
    if current[3] < best[3]:
        best = current
print(best[2].decode('ascii'))
