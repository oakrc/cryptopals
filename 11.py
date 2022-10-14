#!/usr/bin/env python3
import random
import secrets
from typing import Tuple

from mycrypto import (aes_128_cbc_decrypt, aes_128_cbc_encrypt,
                      aes_128_ecb_encrypt, detect_ecb_basic, read_b64)


def encryption_oracle(p: bytes) -> Tuple[int, bytes]:
    k = secrets.token_bytes(16)
    p = secrets.token_bytes(random.randint(5, 10)) \
        + p + secrets.token_bytes(random.randint(5, 10))
    if random.randint(0, 1) == 0:
        return (0, aes_128_ecb_encrypt(p, k))
    else:
        iv = secrets.token_bytes(16)
        return (1, aes_128_cbc_encrypt(p, k, iv))


def test_input(src: bytes, show_results: bool = False):
    successes = 0
    for _ in range(100):
        mode, cipher = encryption_oracle(src)
        prediction = 0 if detect_ecb_basic(cipher) else 1
        if mode == prediction:
            successes += 1
            if show_results:
                print(mode, '=>', prediction)

    print('Success rate: ' + str(successes) + '%')


def main():
    p = aes_128_cbc_decrypt(read_b64('data/10.txt'),
                            b'YELLOW SUBMARINE',
                            b'\0'*16)
    test_input(p, show_results=True)


if __name__ == "__main__":
    main()
