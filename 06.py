from mycrypto import read_b64, score, solve_simple_xor, xor_rep


# hamming distance
def edit_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise Exception("String lengths not equal.")
    count = 0
    for i in range(len(a)):
        # xor'ing gets us the different bits
        count += bin(a[i] ^ b[i]).count('1')
    return count


# transpose a list of bytes like a matrix
def transpose(blocks: list[bytes]) -> list[bytes]:
    transposed = []
    for i in range(len(blocks[0])):
        row = bytearray()
        for block in blocks:
            try:
                row.append(block[i])
            except Exception:
                break
        transposed.append(bytes(row))
    return transposed


# c = ciphertext
# ks = keysize
# returns key
def solve_xor_rep_ks(c: bytes, ks: int) -> bytes:
    # split cipher into key-sized chunks
    blocks = [c[i:i + ks] for i in range(0, len(c), ks)]
    blocks = transpose(blocks)
    key = b''.join([solve_simple_xor(b)[1] for b in blocks])
    return key


# returns best key
# c = cipher
# num_keys = how many best key sizes to try
def solve_xor_rep(c: bytes, num_keys=8) -> list[str]:
    key_sizes = []

    # calculate a list of most likely key sizes using edit distance
    for ks in range(2, 41):
        sum_dist = 0
        for i in range(0, 10, 2):
            sum_dist += edit_distance(c[i * ks:(i + 1) * ks],
                                      c[(i + 1) * ks:(i + 2) * ks]) / ks
        key_sizes.append((ks, sum_dist / 5))

    # least edit distance comes first, which is what we want
    key_sizes = sorted(key_sizes, key=lambda x: x[1])

    # solve the cipher with top key sizes
    keys = [solve_xor_rep_ks(c, key_sizes[i][0]) for i in range(num_keys)]
    # score the keys based on decrypted plaintext
    keys = {k: score(xor_rep(c, k))
            for k in keys}

    return min(keys, key=lambda x: keys[x])  # type: ignore


def main():
    print(solve_xor_rep(read_b64('data/06.txt'), 4))


if __name__ == "__main__":
    main()
