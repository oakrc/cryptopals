#!/usr/bin/env python3
import secrets
import struct
from mycrypto import sha1_keyed_hmac
from sha1 import SHA1
import hashlib



# ===========
# Server-side
# ===========
key = secrets.token_bytes(20)


def generate() -> tuple[bytes, bytes]:
    """Generate a valid message-HMAC pair using a secret key."""
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    return (message, sha1_keyed_hmac(message, key))


def validate_hmac(message: bytes, hmac: bytes) -> bool:
    return sha1_keyed_hmac(message, key) == hmac


# ========
# Attacker
# ========

def attack(message: bytes, hmac: bytes):
    suffix = b';admin=true'
    for key_len in range(1, 32):
        prefixed_message_len = len(message) + key_len
        pad = glue_pad(prefixed_message_len)
        new_message = message + pad + suffix
        processed_message_len = key_len + len(message) + len(pad)

        sha1 = SHA1.continue_from(hmac, processed_message_len)
        sha1.update(suffix)
        new_hmac = sha1.digest()

        if validate_hmac(new_message, new_hmac):
            print(f'Succeeded with key length {key_len}')


def glue_pad(l: int) -> bytes:
    pad = b'\x80'
    pad += b'\x00' * ((56 - (l + 1) % 64) % 64)
    pad += struct.pack(b'>Q', l * 8)
    return pad


if __name__ == '__main__':
    attack(*generate())
