#!/usr/bin/env python3
from mycrypto import to_bytes

from Crypto.Util.number import getPrime, isPrime

def invmod(a, n):
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
    def div(a, b):
        q = a % abs(b)
        return (a - q) // b
    t, new_t = (0, 1)
    r, new_r = (n, a)

    while new_r != 0:
        quotient = div(r, new_r)
        t, new_t = (new_t, t - quotient * new_t)
        r, new_r = (new_r, r - quotient * new_r)

    if r > 1:
        raise ValueError('not invertible')
    if t < 0:
        t += n
    return t


def rsa_encrypt(m_: bytes, e: int, n: int):
    m = int.from_bytes(m_, 'big')
    # TODO: implement breaking the message apart
    assert m < n
    c = pow(m, e, n)
    return to_bytes(c)


def rsa_decrypt(c_: bytes, d: int, n: int):
    c = int.from_bytes(c_, 'big')
    m = pow(c, d, n)
    return to_bytes(m)


def rsa_generate_key_pair(keysize_bits : int, e: int = 65537):
    """Generates a RSA key pair [(e, n), (d, n)]"""
    if not isPrime(e):
        raise ValueError('e needs to be prime')
    while True:
        p = getPrime(keysize_bits // 2)
        q = getPrime(keysize_bits // 2)
        n = p * q
        et = (p - 1) * (q - 1)  # totient
        try:
            d = invmod(e, et)
        except ValueError:
            # Totient must be coprime with public exponent.
            # Generate another key pair.
            continue
        else:
            break

    pubkey = (e, n)
    privkey = (d, n)

    return pubkey, privkey
