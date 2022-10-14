#!/usr/bin/env python3
from mycrypto import read_b64
from Crypto.Cipher import AES

c = read_b64('data/07.txt')
k = b'YELLOW SUBMARINE'
aes = AES.new(k, AES.MODE_ECB)
m = aes.decrypt(c).decode('utf-8')
print(m)
