#!/usr/bin/env python3
import secrets
from base64 import b64decode

from mycrypto import PaddingError, aes_128_cbc_decrypt, aes_128_cbc_encrypt, chop, read_b64s, unpad

# with open('data/17.txt', 'rb') as f:
#     strings = list(filter(None, f.read().split(b'\n')))
#     strings = [b64decode(s) for s in strings]
strings = read_b64s('data/17.txt')
k = secrets.token_bytes(16)


def encrypt() -> bytes:
    iv = secrets.token_bytes(16)
    ch = secrets.choice(strings)
    return iv + aes_128_cbc_encrypt(ch, k, iv)


def decrypt(data: bytes) -> bool:
    try:
        iv = data[:16]
        c = data[16:]
        aes_128_cbc_decrypt(c, k, iv)
        return True
    except PaddingError:
        return False


def main():
    # https://en.wikipedia.org/wiki/Padding_oracle_attack
    plain = [bytearray()]
    cipher = [bytearray(block) for block in chop(encrypt())]
    for i in range(1, len(cipher)):
        plain_block = bytearray(b'\0' * 16)
        for j in reversed(range(16)):
            test = cipher[:i+1]
            test[i-1] = bytearray(secrets.token_bytes(16))
            for k in range(j + 1, 16):
                test[i-1][k] = plain_block[k] ^ cipher[i-1][k] ^ (16 - j)
            done = False
            for byte in range(256):
                test[i-1][j] = byte
                if decrypt(b''.join(test)):
                    plain_block[j] = byte ^ (16 - j) ^ cipher[i-1][j]
                    done = True
                    break
            if not done:
                raise Exception("Correct byte not found")
        plain.append(plain_block)
    print(unpad(b''.join(plain)))


if __name__ == "__main__":
    main()
