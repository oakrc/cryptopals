from base64 import b64decode
from collections import Counter

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


def score(m: bytes, adjusted=True) -> float:
    chi = 0

    mfreq = Counter(m.lower())
    alphas = 0  # number of letters in m
    for a in engfreq:
        alphas += mfreq[ord(a)]

    # calculate chi squared score
    for a in engfreq:
        observed = mfreq[ord(a)]
        expected = engfreq[a] * alphas
        if expected == 0:
            chi += 30000
        else:
            chi += (observed - expected) ** 2 / expected

    # encourage letters and discourage symbols
    # too lazy to improve this
    if adjusted:
        chi += (sum(mfreq.values()) - alphas - mfreq[ord(' ')]) ** 2

    return chi


# (c, k, m, s)
def solve_simple_xor(c: bytes) -> tuple:
    res = (c, '', '', 999999)
    for k in range(20, 127):
        try:
            m = bytes([i ^ k for i in c])
            s = score(m)
            if s < res[3]:
                res = (c, chr(k), m, s)
        except Exception:
            pass
    return res


with open('data/04.txt', 'r') as f:
    ciphers = [bytes.fromhex(c) for c in f.read().split('\n')]

best = ('', '', '', 99999)
for c in ciphers:
    current = solve_simple_xor(c)
    if current[3] < best[3]:
        best = current
print(best)
