"""
w = word size
n = degree of recurrence
m = middle word
r = separation point of one word
a = aicients of the rational normal form twist matrix
b, c = TGFSR(R) tempering bitmasks
s, t = TGFSR(R) tempering bit shifts
u, d, l = additional mersenne twister tempering bit shifts/masks

restriction:
2^(nw - r) is a mersenne prime
"""


class MersenneTwister:
    # x ^ 0xFFFFFFFF zeroes any bits over 32 (the word length).

    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF16
    s, b = 7, 0x9D2C568016
    t, c = 15, 0xEFC6000016
    l = 18  # noqa
    f = 1812433253

    lower_mask = (1 << r) - 1
    upper_mask = (not lower_mask) & 0xFFFFFFFF

    def __init__(self, seed):
        self.seed = seed
        self.index = self.n + 1

        self.state = [None] * self.n
        self.init_state()

    def init_state(self):
        self.index = self.n
        self.state[0] = self.seed
        for i in range(1, self.n):
            self.state[i] = (
                self.f
                * (self.state[i - 1] ^ (self.state[i - 1] >> (self.w - 2)))
                + i
            ) & 0xFFFFFFFF

    def extract_number(self):
        if self.index == self.n:
            self.twist()

        y = self.state[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> 1

        self.index += 1
        return y & 0xFFFFFFFF

    def twist(self):
        for i in range(self.n):
            x = (self.state[i] & self.upper_mask) + (
                self.state[(i + 1) % self.n] & self.lower_mask
            )
            xA = x >> 1
            if x % 2:
                xA ^= self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ xA
        self.index = 0


if __name__ == '__main__':
    mt = MersenneTwister(68)
    rands = [mt.extract_number() for _ in range(1000)]
    mt2 = MersenneTwister(68)
    rands2 = [mt2.extract_number() for _ in range(1000)]
    assert rands == rands2
    print('Passed')
