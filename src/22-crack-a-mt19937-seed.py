from importlib import import_module
from random import randint
from time import sleep, time

twentyone = import_module("21-implement-the-mt19937-mersenne-twister-rng")
MersenneTwister = twentyone.MersenneTwister


def random_wait():
    rand_wait = randint(40, 1000) // 100  # Not patient enough for this.
    print(f"Sleeping {rand_wait} seconds...")
    sleep(rand_wait)


def crack_seed(random_bit):
    for i in range(int(time()), int(time()) - 1000, -1):
        if MersenneTwister(i).extract_number() == random_bit:
            return i
    raise Exception("Seed not found.")  # Shouldn't happen.


if __name__ == "__main__":
    random_wait()
    seed = int(time())
    mt = MersenneTwister(seed)
    random_wait()
    random_bit = mt.extract_number()
    assert seed == crack_seed(random_bit)
    print("Passed")
