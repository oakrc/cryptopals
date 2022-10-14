#!/usr/bin/env python3
# repeating-key xor
# m = message (plaintext / message)
# k = key
def xor_rep(m: bytes, k: bytes) -> bytes:
    return bytes([ch ^ k[i % len(k)] for i, ch in enumerate(m)])


pt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

print(xor_rep(pt, b'ICE').hex())
