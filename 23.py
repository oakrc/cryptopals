#!/usr/bin/env python3
from time import time
from mycrypto import MT19937

prng = MT19937(int(time()))
mirror = MT19937(0)

for i in range(prng.n):
    rnd = prng.get()
    mirror.set(i, mirror.untemper(rnd))

for i in range(prng.n):
    assert prng.get() == mirror.get()
