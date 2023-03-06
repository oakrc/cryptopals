#!/usr/bin/env python3
import secrets
from base64 import b64encode, b64decode

from mycrypto import aes_128_cbc_decrypt, aes_128_cbc_encrypt, chop, xor_rep

k = secrets.token_bytes(16)
pt = b'A' * 16 + b'B' * 16 + b'C' * 16

def intercept_ciphertext() -> bytes:
    return aes_128_cbc_encrypt(pt, k, k)


def ascii_compliant(msg: bytes) -> bool:
    return not any([b > 127 for b in msg])


def modify(ct: bytes) -> bytes:
    blocks = chop(ct)
    blocks[1] = b'\x00' * 16
    blocks[2] = blocks[0]
    return b''.join(blocks)


def forward_to_recipient(ct: bytes):
    pt = aes_128_cbc_decrypt(ct, k, k)
    if not ascii_compliant(ct):
        raise ValueError("Corrupted message: " + b64encode(pt).decode('ascii'))


def attack():
    ct_original = intercept_ciphertext()
    ct_modified = modify(ct_original)
    pt_modified = []
    try:
        forward_to_recipient(ct_modified)
    except ValueError as e:
        pt_modified = chop(b64decode(str(e)[len("Corrupted message: "):].encode('ascii')))
    assert len(pt_modified) != 0

    recovered_key = xor_rep(pt_modified[0], pt_modified[2])
    assert recovered_key == k

    pt_original = aes_128_cbc_decrypt(ct_original, recovered_key, recovered_key)
    assert pt_original == pt

    print('Succeeded')

if __name__ == '__main__':
    attack()
