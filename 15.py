#!/usr/bin/env python3
# undo PKCS#7 padding
def unpad(m: bytes) -> bytes:
    padding = m[-m[-1]:]
    if padding[:-1] != padding[1:]:
        raise Exception("Invalid padding")
    return m[:-m[-1]]
