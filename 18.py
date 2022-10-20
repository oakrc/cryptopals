#!/usr/bin/env python3
from pwn import p64
from Crypto.Cipher import AES

from mycrypto import chop, read_b64, xor_rep

c = read_b64('data/18.txt')
k = b'YELLOW SUBMARINE'
n = b'\x00'*8  # nonce

def aes_128_ctr_crypt(src: bytes, k: bytes, nonce: bytes) -> bytes:
    sink = b''
    blocks = chop(src)
    for i, block in enumerate(blocks):
        aes = AES.new(k, AES.MODE_ECB)
        block_key = aes.encrypt(nonce + p64(i))
        sink += xor_rep(block, block_key)
    return sink

def main():
    print(aes_128_ctr_crypt(c, k, n).decode('utf-8'))

if __name__ == '__main__':
    main()
