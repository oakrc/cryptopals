#!/usr/bin/env python3

import secrets

from pwn import p64
from mycrypto import aes_128_ctr_encrypt, chop, read_b64, xor_rep
from Crypto.Cipher import AES


aes = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
m = aes.decrypt(read_b64('data/25.txt'))

key = secrets.token_bytes(16)
nonce = b'\x00' * 8
ct = aes_128_ctr_encrypt(m, key, nonce)

def edit_byte(ct: bytes, key: bytes, idx: int, new_byte: int) -> bytes:
    """
    Replace a byte in a CTR-encrypted ciphertext.
    Assumes nonce is 16 null bytes.
    """
    nonce = b'\x00' * 8
    blocks = chop(ct)
    aes = AES.new(key, AES.MODE_ECB)

    # get plaintext
    block_key = aes.encrypt(nonce + p64(idx // 16))
    assert(len(block_key) == 16)
    block_pt = bytearray(xor_rep(blocks[idx // 16], block_key))
    assert(len(block_pt) <= 16)

    # edit plaintext
    block_pt[idx % 16] = new_byte

    # encrypt and replace entire block
    # (CTR doesn't need padding -- can be less than block size)
    new_ct = bytearray(ct)
    new_ct[idx - idx % 16:len(block_pt)] = xor_rep(block_pt, block_key)
    return bytes(new_ct)

def edit_api(ct: bytes, idx: int, new_byte) -> bytes:
    global key
    return edit_byte(ct, key, idx, new_byte)

def break_rarw(ct, edit) -> bytes:
    plain = bytearray()
    for index, cipher_byte in enumerate(ct):
        key_byte = edit(ct, index, 0)[index]
        plain.append(cipher_byte ^ key_byte)

    return bytes(plain)

if __name__ == '__main__':
    print(break_rarw(ct, edit_api))
