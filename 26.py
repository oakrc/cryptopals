#!/usr/bin/env python3
import secrets

from mycrypto import aes_128_ctr_decrypt, aes_128_ctr_encrypt, chop

k = secrets.token_bytes(16)
nonce = secrets.token_bytes(8)


def encrypt(i: bytes) -> bytes:
    i = i.replace(b';', b'%3B')
    i = i.replace(b'=', b'%3D')
    i = b'comment1=cooking%20MCs;userdata=' + i
    i += b';comment2=%20like%20a%20pound%20of%20bacon'
    return aes_128_ctr_encrypt(i, k, nonce)


def is_admin(data: bytes) -> bool:
    data = aes_128_ctr_decrypt(data, k, nonce)
    return b';admin=true;' in data


def main():
    original = b'a' * 16
    desired = b';admin=true;aaaa'
    c = encrypt(original)
    bitflips = bytes([o ^ d for o, d in zip(original, desired)])
    c_blks = chop(c)
    c_blks[2] = bytes([c ^ f for c, f in zip(c_blks[2], bitflips)])
    assert is_admin(b''.join(c_blks))
    print('Succeeded')


if __name__ == '__main__':
    main()
