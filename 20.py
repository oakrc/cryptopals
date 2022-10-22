#!/usr/bin/env python3
import secrets
from mycrypto import aes_128_ctr_crypt, chop, read_b64s, solve_xor_rep_ks, xor_rep
from pwn import p64

# prepare ciphers
messages = read_b64s('data/20.txt')
k = secrets.token_bytes(16)
ciphers = [aes_128_ctr_crypt(m, k, p64(0)) for m in messages]

# find the shortest one and chop others with the shortest one's length as block size
# concat the first blocks together and we've got a repeating key XOR cipher to solve
ciphers.sort(key=len)
bs = len(ciphers[0])
ciphers = b''.join([chop(cipher, bs)[0] for cipher in ciphers])
key = solve_xor_rep_ks(ciphers, bs)
for m in chop(xor_rep(ciphers, key), bs):
    print(m.decode('ascii'))
