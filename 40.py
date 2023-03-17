#!/usr/bin/env python3

from gmpy2 import iroot, mpz # type: ignore

from mycrypto.mycrypto import to_bytes
from mycrypto.rsa import invmod, rsa_generate_key_pair, rsa_encrypt

pubkeys = []
privkeys = []

for i in range(3):
    pubkey, privkey = rsa_generate_key_pair(256, 3)
    pubkeys.append(pubkey)
    privkeys.append(privkey)

pt = b'Hello RSA'
cts = [int.from_bytes(rsa_encrypt(pt, *key), 'big') for key in pubkeys]

result = 0
for i in range(3):
    m_s_i = 1
    for j in range(3):
        if j == i:
            continue
        m_s_i *= pubkeys[j][1]
    result += cts[i] * m_s_i * invmod(m_s_i, privkeys[i][1])

# "leave off the final modulus operation"
# I call BS
result %= pubkeys[0][1] * pubkeys[1][1] * pubkeys[2][1]

pt_int = int.from_bytes(pt, 'big')
root, is_exact = iroot(mpz(result), 3)
assert is_exact
m = to_bytes(int(root))

print(m)
assert pt_int == root
print('Successfully decrypted message')
