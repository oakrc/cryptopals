#!/usr/bin/env python3

import secrets

from pwn import p64
from mycrypto import aes_128_ctr_encrypt, chop, read_b64, xor_rep
from Crypto.Cipher import AES


aes = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
# there are two extra \x04 bytes at the end for some reason
m = aes.decrypt(read_b64('data/07.txt'))[-2]

key = secrets.token_bytes(16)
nonce = secrets.token_bytes(16)
ct = aes_128_ctr_encrypt(m, key, nonce)
print(m)

def edit(ct, key, idx, new):
    global nonce
    blocks = chop(ct)
    aes = AES.new(key, AES.MODE_ECB)
    # get plaintext
    block_key = aes.encrypt(nonce + p64(idx // 16))
    # edit plaintext
    block_pt = xor_rep(blocks[idx // 16], block_key)
    assert len(new) == 1
    block_pt[idx % 16] = new
    # reencrypt to ciphertext
    # replace entire block
