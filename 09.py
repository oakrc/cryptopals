#!/usr/bin/env python3
# PKCS#7 padding
# assuming bs = 16
def pad(m: bytes):
    pad_len = 16 - len(m) % 16
    return m + pad_len * bytes([pad_len])


# undo PKCS#7 padding
# assuming bs = 16
def unpad(m: bytes) -> bytes:
    return m[:-m[-1]]
