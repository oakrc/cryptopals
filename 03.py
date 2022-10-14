#!/usr/bin/env python3
from collections import Counter

c = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
exp = '^[A-Za-z !\'"?:()\\[\\]-_/@{}\\*\\.;,]+$'
# https://gist.github.com/pozhidaevak/0dca594d6f0de367f232909fe21cdb2f
engfreq = {
    'e': 12.0, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31,
    'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32,
    'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30,
    'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
    'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
}
for i in engfreq:
    engfreq[i] /= 100


# c = bytes
# k = num
def xor(c, k):
    m = bytearray()
    for i in c:
        m.append(i ^ k)
    return m


# m = str (decoded message)
def score(m, adjusted=True):
    chi = 0

    mfreq = Counter(m.lower())
    alphas = 0  # number of letters in m
    for a in engfreq:
        alphas += mfreq[a]

    # calculate chi squared score
    for a in engfreq:
        observed = mfreq[a]
        expected = engfreq[a] * alphas
        chi += (observed - expected) ** 2 / expected

    # encourage letters and discourage symbols
    if adjusted:
        chi += (sum(mfreq.values()) - alphas - mfreq[' ']) ** 2

    return chi


# (c, k, m, s)
def solve_simple_xor(c: bytes, log_best=True) -> tuple:
    res = (c, '', '', 999999)
    for k in range(128):
        try:
            m = xor(c, k)
            m = m.decode('ascii')
            s = score(m)
            if s < res[3]:
                if log_best:
                    print(k, '/', s, '/', m)
                res = (c, chr(k), m, s)
        except Exception:
            pass
    return res


print(solve_simple_xor(bytes.fromhex(c), log_best=False)[2])
