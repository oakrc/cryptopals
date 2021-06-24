import secrets
from collections import Counter

from mycrypto import aes_128_ecb_encrypt, chop, detect_ecb_basic, read_b64

k = secrets.token_bytes(16)
suffix = read_b64('data/12.txt')


def oracle(p: bytes) -> bytes:
    return aes_128_ecb_encrypt(p + suffix, k)


# only works without prefix
def guess_bs() -> int:
    for bs in range(4, 64):
        c = oracle(b'a' * bs * 2)
        freq = Counter(chop(c, bs))
        if max(freq.values()) > 1:
            return bs
    return -1


def solve_ecb_suffix(bs: int) -> bytes:
    suffix = b''
    prev = b'a' * bs
    # might not be accurate due to padding but whatever
    num_blocks = len(chop(oracle(b'')))
    # i is the block where the leak is happening
    for i in range(num_blocks):
        known = b''
        while len(known) < bs:
            input_block = prev[len(known) + 1:]
            leak = chop(oracle(input_block))[i]
            lookup = {}
            for guess in range(128):
                plain = input_block + known + bytes([guess])
                outcome = chop(oracle(plain))[0]
                lookup[outcome] = guess
            try:
                known += bytes([lookup[leak]])
            except Exception:
                # hit the padding
                # last byte is unneeded
                return (suffix + known)[:-1]
        assert len(known) == bs
        suffix += known
        prev = known
    return suffix


def main():
    bs = guess_bs()
    assert bs == 16
    assert detect_ecb_basic(oracle(b'a' * bs * 4))
    print(solve_ecb_suffix(bs).decode('ascii'))


if __name__ == "__main__":
    main()
