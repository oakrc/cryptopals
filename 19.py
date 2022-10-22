#!/usr/bin/env python3

import secrets
from mycrypto import aes_128_ctr_crypt, read_b64s


messages = read_b64s('data/19.txt')
k = secrets.token_bytes(16)
ciphers = [aes_128_ctr_crypt(m, k, b'\x00'*8) for m in messages]
ciphers = sorted(ciphers, key=len)
print([len(c) for c in ciphers])

# Screw this. Onto 20.
