#!/usr/bin/env python3

from Crypto.Util.number import getPrime

from mycrypto import to_bytes


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
    c = pow(m, e, n)
    return to_bytes(c)


def rsa_decrypt(c_: bytes, d: int, n: int):
    c = int.from_bytes(c_, 'big')
    m = pow(c, d, n)
    return to_bytes(m)


def main():
    while True:
        p = getPrime(2048)
        q = getPrime(2048)
        n = p * q
        et = (p - 1) * (q - 1)  # totient
        e = 65537
        try:
            d = invmod(e, et)
        except ValueError:
            print('Totient is coprime with public exponent. Generating another key pair.')
        else:
            break

    pubkey = (e, n)
    privkey = (d, n)

    m = b'Hello RSA'
    c = rsa_encrypt(m, *pubkey)
    md = rsa_decrypt(c, *privkey)

    assert m == md
    print('RSA implementation works')


if __name__ == '__main__':
    main()
