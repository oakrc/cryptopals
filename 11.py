import random
import secrets
from typing import Tuple

from mycrypto import (aes_128_cbc_decrypt, aes_128_cbc_encrypt,
                      aes_128_ecb_encrypt, detect_ecb, read_b64)


def encryption_oracle(p: bytes) -> Tuple[int, bytes]:
    k = secrets.token_bytes(16)
    p = secrets.token_bytes(random.randint(5, 10)) \
        + p + secrets.token_bytes(random.randint(5, 10))
    if random.randint(0, 1) == 0:
        return (0, aes_128_ecb_encrypt(p, k))
    else:
        iv = secrets.token_bytes(16)
        return (1, aes_128_cbc_encrypt(p, k, iv))


p = aes_128_cbc_decrypt(read_b64('data/10.txt'),
                        b'YELLOW SUBMARINE',
                        b'\0'*16)

successes = 0
for _ in range(100):
    mode, cipher = encryption_oracle(p)
    if mode == 0 if detect_ecb(cipher) else 1:
        successes += 1

print('Success rate: ' + str(successes) + '%')
