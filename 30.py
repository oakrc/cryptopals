#!/usr/bin/env python3
#!/usr/bin/env python
from md4 import MD4
import secrets
import struct



# ===========
# Server-side
# ===========
key = secrets.token_bytes(20)


def md4_keyed_hmac(message: bytes, key: bytes) -> bytes:
    md4 = MD4()
    md4.update(key)
    md4.update(message)
    return md4.digest()


def generate() -> tuple[bytes, bytes]:
    """Generate a valid message-HMAC pair using a secret key."""
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    return (message, md4_keyed_hmac(message, key))


def validate_hmac(message: bytes, hmac: bytes) -> bool:
    return md4_keyed_hmac(message, key) == hmac


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

        md4 = MD4.continue_from(hmac, processed_message_len)
        md4.update(suffix)
        new_hmac = md4.digest()

        if validate_hmac(new_message, new_hmac):
            print(f'Succeeded with key length {key_len}')


def glue_pad(l: int) -> bytes:
    return  b'\x80' + b'\x00' * ((55 - l) % 64) + struct.pack('<Q', l * 8)


if __name__ == '__main__':
    attack(*generate())
