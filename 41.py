#!/usr/bin/env python3
from mycrypto import to_bytes
from mycrypto.rsa import invmod, rsa_generate_key_pair, rsa_encrypt, rsa_decrypt

p = b"{time: 1356304276, social: '555-55-5555',}"
pub, priv = rsa_generate_key_pair(1024)

c = int.from_bytes(rsa_encrypt(p, *pub), 'big')

e, n = pub
s = 2 # 1 < s < n

c_ = (pow(s, e, n) * c) % n

p_ = int.from_bytes(rsa_decrypt(to_bytes(c_), *priv), 'big')

p_recovered = (p_ * invmod(s, n)) % n
p_recovered = to_bytes(p_recovered)

assert p_recovered == p
print('Successfully recovered plaintext')
