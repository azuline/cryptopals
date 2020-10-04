"""
Create the MT19937 stream cipher and break it
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from random import randint

from set1.c02 import xor
from set3.c21 import MersenneTwister

MAX_SEED = (1 << 16) - 1


def crypt(plaintext, seed):
    mt = MersenneTwister(seed)

    keystream = b""
    for i in range(0, len(plaintext), 4):
        keystream += mt.extract_number().to_bytes(length=4, byteorder="little")

    return xor(plaintext, keystream)


def crack_seed(ciphertext):
    for seed in range(0, MAX_SEED):
        decrypted = crypt(ciphertext, seed)
        if decrypted.endswith(b"A" * 14):
            return seed


if __name__ == "__main__":
    seed = randint(0, MAX_SEED)
    plaintext = b"helloooAAAAAAAAAAAAAA"

    ciphertext = crypt(plaintext, seed)
    assert seed == crack_seed(ciphertext)

    print("Passed")
