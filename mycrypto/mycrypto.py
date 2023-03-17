#!/usr/bin/env python3
import logging
import time
import string

from base64 import b64decode
from collections import Counter
from pwn import p64 # type: ignore
from math import ceil

from Crypto.Cipher import AES

from .hash import SHA1

logging.basicConfig()

def solve_simple_xor(c: bytes) -> tuple:
    # (cipher, key, message, score)
    res = (c, b'', b'', float('inf'))
    for k in range(256):
        try:
            m = bytes([i ^ k for i in c])
            s = score(m)
            if s < res[3]:
                res = (c, bytes([k]), m, s)
        except Exception as e:
            print(e)
    return res


# repeating-key xor
# m = message (plaintext / message)
# k = key
def xor_rep(m: bytes, k: bytes) -> bytes:
    return bytes([ch ^ k[i % len(k)] for i, ch in enumerate(m)])


eng_regex = '^[A-Za-z !\'"?:()-/\\.;,]+$'
eng_regex_full = '^[A-Za-z !\'"?:()\\[\\]-_/@{}\\*\\.;,]+$'

# English letter frequency
eng_freq = {
    'e': 12.0, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
    'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
    'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
    'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
    'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07,
}
eng_punct = {
    # approximated:
    '.': 0.01, ',': 0.01, '"': 0.004,'\'':0.004,'-': 0.003,'!': 0.001,
    ':': 0.001,';': 0.001
}
for i in eng_freq:
    eng_freq[i] /= 100


# lower score means closer to english
# m = message
def score(src: bytes) -> float:
    if len(src) == 0:
        return float('inf')
    chi = 0
    m = src

    # unprintable text cannot be English
    for ch in m:
        if ch not in string.printable.encode('ascii'):
            return float('inf')

    # removing non-latin characters
    nonlatin = string.whitespace + string.punctuation + string.digits
    m = src.translate(None, nonlatin.encode('ascii'))
    if len(m) == 0:
        return float('inf')

    # calculate letter frequency in message
    dist = Counter(m.lower())

    # calculate chi squared score
    for a in eng_freq:
        observed = dist[ord(a)] / len(m)
        expected = eng_freq[a]
        chi += (observed - expected) ** 2 / expected

    # scale score based on how many non-English characters were removed
    ratio = len(m) / len(src)
    return chi / ratio


# PKCS#7 padding
def pad(m: bytes, bs: int = 16) -> bytes:
    pad_len = bs - len(m) % bs
    if pad_len == bs:
        return m
    return m + pad_len * bytes([pad_len])

#
# undo PKCS#7 padding
def unpad(m: bytes) -> bytes:
    padding = m[-m[-1]:]
    if padding[:-1] != padding[1:]:
        # not padded, return as is
        return m
    # TODO: check if all padding bytes are valid
    return m[:-m[-1]]


# chop message into blocks of size bs
# m should be padded beforehand
def chop(m: bytes, bs: int = 16) -> list[bytes]:
    return [m[i:i + bs] for i in range(0, len(m), bs)]


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XORing bytes of unequal length is not allowed.")
    return bytes([i ^ j for i, j in zip(a, b)])


def aes_128_ecb_encrypt(src: bytes, k: bytes) -> bytes:
    src = pad(src)
    aes = AES.new(k, AES.MODE_ECB)
    return aes.encrypt(src)


def aes_128_ecb_decrypt(src: bytes, k: bytes) -> bytes:
    aes = AES.new(k, AES.MODE_ECB)
    return unpad(aes.decrypt(src))


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


def aes_128_ctr_encrypt(src: bytes, k: bytes, nonce: bytes) -> bytes:
    sink = b''
    blocks = chop(src)
    assert(len(nonce) == 8)
    for i, block in enumerate(blocks):
        aes = AES.new(k, AES.MODE_ECB)
        block_key = aes.encrypt(nonce + p64(i))
        sink += xor_rep(block, block_key)
    return sink

def aes_128_ctr_decrypt(src: bytes, k: bytes, nonce: bytes) -> bytes:
    sink = b''
    blocks = chop(src)
    assert(len(nonce) == 8)
    for i, block in enumerate(blocks):
        aes = AES.new(k, AES.MODE_ECB)
        block_key = aes.encrypt(nonce + p64(i))
        sink += xor_rep(block, block_key)
    return sink

def read_b64(filename: str) -> bytes:
    with open(filename, 'r') as f:
        c = f.read()
        c = b64decode(c)
    return c

def read_b64s(filename: str) -> list[bytes]:
    decoded = []
    with open(filename, 'r') as f:
        for line in f.readlines():
            decoded.append(b64decode(line.rstrip()))
    return decoded



def aes_128_cbc_works(m: bytes, k: bytes, iv: bytes = b'\0'*16):
    c = aes_128_cbc_encrypt(m, k, iv)
    pt = aes_128_cbc_decrypt(c, k, iv)
    return m == pt


# count maximum number of identical blocks
def max_dupe_blks(c: bytes, bs: int = 16) -> int:
    freq = Counter(chop(c, bs))
    return max(freq.values())


# returns True if ECB is likely used
# super basic method, so only works
# when plaintext is user-controlled
# so we can inject tons of repeating chars
def detect_ecb_basic(c: bytes) -> bool:
    return True if max_dupe_blks(c) > 1 else False


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
    blocks = transpose(chop(c, ks))
    key = b''.join([solve_simple_xor(b)[1] for b in blocks])
    return key

def unix_time():
    return int(time.time())

def sha1_keyed_hmac(message: bytes, key: bytes) -> bytes:
    sha1 = SHA1()
    sha1.update(key)
    sha1.update(message)
    return sha1.digest()


def to_bytes(s_: int) -> bytes:
    s: bytes = b'\x00'
    if s_ != 0:
        s = s_.to_bytes(ceil(s_.bit_length() / 8), 'big')
    return s
