import secrets
from string import printable
import re
from collections import Counter

from mycrypto import (aes_128_ecb_encrypt, chop, detect_ecb_basic, read_b64,
                      score, eng_regex)

k = secrets.token_bytes(16)
suffix = read_b64('data/12.txt')
print(score(suffix))


def oracle(p: bytes) -> bytes:
    return aes_128_ecb_encrypt(p + suffix, k)


def guess_bs() -> int:
    for bs in range(4, 64):
        c = oracle(b'a' * bs * 2)
        freq = Counter(chop(c, bs))
        if max(freq.values()) > 1:
            return bs
    return -1


assert guess_bs() == 16
bs = 16
assert detect_ecb_basic(oracle(b'a'*16*4))




def main():
    solve_ecb_basic()


if __name__ == "__main__":
    main()
