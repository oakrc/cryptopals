#!/usr/bin/env python3
import sys

from math import ceil

from gmpy2 import iroot, mpz # type: ignore
from Crypto.Hash import SHA1

from mycrypto.rsa import rsa_generate_key_pair

def generate_sig(hash: bytes, pubkey: tuple[int, int]):
    e, n = pubkey
    if e != 3:
        raise ValueError('e != 3')
    key_size = ceil(n.bit_length() / 8) * 8

    # the extra a makes N % 3 == 0
    D = b'\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00ASN.1' + hash
    D_len = len(D) * 8
    print(D_len)
    N = 2 ** D_len - int.from_bytes(D, 'big')
    garbage = -N % 3
    N += garbage
    print(garbage)
    # ???



pubkey, privkey = rsa_generate_key_pair(3072, 3)
m = b'hi mom'
sha1 = SHA1.new()
sha1.update(m)
generate_sig(sha1.digest(), pubkey)
