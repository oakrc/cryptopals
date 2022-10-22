#!/usr/bin/env python3
class MT19937:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908b0df
    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18
    f = 1812433253

    def __init__(self, seed) -> None:
        self.MT = [0] * self.n
        self.index = self.n+1

        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = self.lowest_bits(~self.lower_mask, self.w)

        self.MT[0] = seed
        for i in range(1, self.n - 1):
            self.MT[i] = self.lowest_bits(self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i, self.w)

    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0
        pass

    def get(self):
        if self.index >= self.n:
            self.twist()
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1
        return (self.lowest_bits(y, self.w))

    def lowest_bits(self, n: int, bits: int):
        mask = (1 << bits) - 1
        return n & mask


if __name__ == '__main__':
    rand = MT19937(1122)
    for i in range(30):
        print(rand.get())
