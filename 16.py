#!/usr/bin/env python3
import secrets

from mycrypto import aes_128_cbc_decrypt, aes_128_cbc_encrypt, chop

k = secrets.token_bytes(16)
iv = secrets.token_bytes(16)


def encrypt(i: bytes) -> bytes:
    i = i.replace(b';', b'%3B')
    i = i.replace(b'=', b'%3D')
    i = b'comment1=cooking%20MCs;userdata=' + i
    i += b';comment2=%20like%20a%20pound%20of%20bacon'
    return aes_128_cbc_encrypt(i, k, iv)


def is_admin(data: bytes) -> bool:
    data = aes_128_cbc_decrypt(data, k, iv)
    return b';admin=true;' in data


def main():
    original = b'a' * 16
    desired = b';admin=true;aaaa'
    c = encrypt(original * 2)
    # Bit flips can be used to directly modify
    # the plaintext of the next block. This is
    # because the next decrypted block is XOR'd
    # with the previous ciphertext block to
    # get the plaintext
    bitflips = bytes([o ^ d for o, d in zip(original, desired)])
    c_blks = chop(c)
    c_blks[1] = bytes([c ^ f for c, f in zip(c_blks[1], bitflips)])
    assert is_admin(b''.join(c_blks))
    print('Succeeded')


if __name__ == '__main__':
    main()
