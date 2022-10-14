#!/usr/bin/env python3
import random
from mycrypto import aes_128_ecb_encrypt, chop, max_dupe_blks, read_b64
import secrets


k = secrets.token_bytes(16)
prefix = secrets.token_bytes(random.randint(1, 10))
suffix = read_b64('data/12.txt')


def oracle(p: bytes) -> bytes:
    return aes_128_ecb_encrypt(prefix + p + suffix, k)


def guess_bs():
    last_len = len(oracle(b''))
    # index at which 1st change in length occurred
    i_chg = -1
    for i in range(1, 256):
        current_len = len(oracle(b'a' * i))
        if current_len != last_len:
            if i_chg == -1:
                i_chg = i
                last_len = current_len
            else:
                return i - i_chg
    return -1


def solve_ecb_suffix_hard(bs: int = 16):
    fill_size = 0
    # figure out prefix length -> required padding
    for n in range(bs):
        if max_dupe_blks(oracle(b'f' * n + b'a' * bs * 2)) > 1:
            fill_size = n
            break

    suffix = b''
    prev = b'a' * bs
    # might not be accurate due to padding but whatever
    num_blocks = len(chop(oracle(b'f' * fill_size))) - 1
    # i is the block where the leak is happening
    for i in range(1, num_blocks + 1):
        known = b''
        while len(known) < bs:
            input_block = b'f' * fill_size + prev[len(known) + 1:]
            leak = chop(oracle(input_block))[i]
            lookup = {}
            for guess in range(128):
                plain = input_block + known + bytes([guess])
                outcome = chop(oracle(plain))[1]
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
    print(solve_ecb_suffix_hard(guess_bs()).decode('ascii'))


if __name__ == "__main__":
    main()
