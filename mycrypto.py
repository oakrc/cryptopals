import logging
from base64 import b64decode
from collections import Counter

from Crypto.Cipher import AES


# (c, k, m, s)
def solve_simple_xor(c: bytes) -> tuple:
    res = (c, b'', b'', 999999)
    for k in range(20, 127):
        try:
            m = bytes([i ^ k for i in c])
            s = score(m)
            if s < res[3]:
                res = (c, bytes([k]), m, s)
        except Exception:
            pass
    return res


# repeating-key xor
# m = message (plaintext / message)
# k = key
def xor_rep(m: bytes, k: bytes) -> bytes:
    return bytes([ch ^ k[i % len(k)] for i, ch in enumerate(m)])


# English letter frequency
engfreq = {
    'e': 12.0, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
    'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
    'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
    'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
    'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
}
for i in engfreq:
    engfreq[i] /= 100


# lower score means closer to english
# m = message
def score(m: bytes, adjusted=True) -> float:
    chi = 0

    mfreq = Counter(m.lower())
    alphas = 0  # number of letters in m
    for a in engfreq:
        alphas += mfreq[ord(a)]
        logging.debug(alphas)

    # calculate chi squared score
    for a in engfreq:
        observed = mfreq[ord(a)]
        expected = engfreq[a] * alphas
        if expected == 0:
            logging.debug("Zero expected letters")
            chi += 30000
        else:
            chi += (observed - expected) ** 2 / expected

    # encourage letters and discourage symbols
    # too lazy to improve this
    if adjusted:
        chi += 3 * (sum(mfreq.values()) - alphas - mfreq[ord(' ')])

    return chi


# PKCS#7 padding
# assuming bs = 16
def pad(m: bytes, bs: int = 16):
    pad_len = bs - len(m) % bs
    return m + pad_len * bytes([pad_len])


# undo PKCS#7 padding
# assuming bs = 16
def unpad(m: bytes) -> bytes:
    return m[:-m[-1]]


# chop message into blocks of size bs
# m is padded
def chop(m: bytes, bs: int = 16) -> list[bytes]:
    return [m[i:i + bs] for i in range(0, len(m), bs)]


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise Exception("XORing str's of unequal length is not allowed.")
    return bytes([i ^ j for i, j in zip(a, b)])


def aes_128_ecb_encrypt(src: bytes, k: bytes) -> bytes:
    src = pad(src)
    aes = AES.new(k, AES.MODE_ECB)
    return aes.encrypt(src)


# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
# the diagram's super helpful
def aes_128_cbc_encrypt(src: bytes, k: bytes, iv: bytes) -> bytes:
    sink = b''
    src = pad(src)
    last = iv
    for block in chop(src):
        aes = AES.new(k, AES.MODE_ECB)
        last = aes.encrypt(xor(block, last))
        sink += last
    return sink


def aes_128_cbc_decrypt(src: bytes, k: bytes, iv: bytes) -> bytes:
    sink = b''
    last = iv
    for block in chop(src):
        aes = AES.new(k, AES.MODE_ECB)
        sink += xor(aes.decrypt(block), last)
        last = block
    return unpad(sink)


def read_b64(filename: str) -> bytes:
    with open(filename, 'r') as f:
        c = f.read()
        c = b64decode(c)
    return c


def aes_128_cbc_works(m: bytes, k: bytes, iv: bytes = b'\0'*16):
    c = aes_128_cbc_encrypt(m, k, iv)
    pt = aes_128_cbc_decrypt(c, k, iv)
    return m == pt


# returns True if ECB is likely used
def detect_ecb(c: bytes) -> bool:
    freq = Counter(chop(c))
    # if there are any repeating blocks then return true
    return True if max(freq.values()) > 1 else False
