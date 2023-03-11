#!/usr/bin/env python3
from sha1 import SHA1
import secrets

def sha1_keyed_hmac(message: bytes, key: bytes) -> bytes:
    sha1 = SHA1()
    sha1.update(key)
    sha1.update(message)
    return sha1.digest()

def test_sha1_keyed_hmac() -> bool:
    key = secrets.token_bytes(32)
    m1 = secrets.token_bytes(64)
    hmac1 = sha1_keyed_hmac(m1, key)
    m2 = secrets.token_bytes(64)
    hmac2 = sha1_keyed_hmac(m2, key)


    if hmac1 == hmac2:
        return False

    m1_mod = bytearray(m1)
    m1_mod[3] = m1[3] ^ 32
    hmac1_mod = sha1_keyed_hmac(m1_mod, key)
    if hmac1 == hmac1_mod:
        return False

    sha1 = SHA1()
    sha1.update(m1)
    if hmac1 == sha1.digest():
        return False
    return True

if __name__ == '__main__':
    assert test_sha1_keyed_hmac()
    print('Succeeded')
