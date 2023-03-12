#!/usr/bin/env python3
from random import randint
from secrets import token_bytes

from mycrypto import chop, unix_time, xor_rep
from mycrypto.random import MT19937

def rand_crypt(m: bytes, k: bytes) -> bytes:
    seed = int.from_bytes(k, 'big', signed=False)
    prng = MT19937(seed)
    sink = b''
    for block in chop(m, 4):
        ks = prng.get().to_bytes(4, byteorder='big')
        sink += xor_rep(block, ks)
    return sink

# Cipher works
time = unix_time() & 0xffff
key = time.to_bytes(2, byteorder='big')
pt = b'Test Test Test'
ct = rand_crypt(pt, key)
assert pt == rand_crypt(ct, key)

# Brute-force key
key = token_bytes(2)
pt = token_bytes(randint(5, 10)) + b'A'*14
ct = rand_crypt(pt, key)
for i in range(2 ** 16):
    current_key = i.to_bytes(2, byteorder='big')
    result = rand_crypt(ct, current_key)
    if result.endswith(b'A'*14):
        assert key == current_key
        break
print(b'Known plain-text: Key brute-forced')

# Determine if bytes are password reset token
def generate_token(n: int, seed: int) -> bytes:
    prng = MT19937(seed)
    sink = b''
    for _ in range(n // 4 + 1):
        sink += prng.get().to_bytes(4, byteorder='big')
    return sink[:-(4 - (n % 4))]

def detect_token(t: bytes, seed: int) -> bool:
    return t == generate_token(len(t), seed)

t = unix_time()
assert detect_token(generate_token(32, t), t)
assert not detect_token(token_bytes(32), t)
print('Token detection works')
