# INCOMPLETE

from importlib import import_module
from random import randint

twentyone = import_module("21-implement-the-mt19937-mersenne-twister-rng")
MersenneTwister = twentyone.MersenneTwister


def clone_mt19937(twister):
    clone = MersenneTwister(0)

    for i in range(624):
        rand = twister.extract_number()
        clone.state[i] = untemper(twister, rand)
        assert twister.state[i] == clone.state[i]

    return clone


def untemper(twister, byte):
    # Invert these... somehow.
    # I am skipping this since non-trivial bitwise operations like this are
    # going to lead me in circles for days, likely.
    byte ^= byte >> twister.l
    byte ^= (byte << twister.t) & twister.c
    byte ^= (byte << twister.s) & twister.b
    byte ^= (byte >> twister.u) & twister.d
    return byte


if __name__ == "__main__":
    twister = MersenneTwister(randint(0, 1000))
    clone = clone_mt19937(twister)
    for _ in range(624):
        assert twister.extract_number() == clone.extract_number()
    print("Passed")
