from importlib import import_module
from random import randint

twentyone = import_module('21-implement-the-mt19937-mersenne-twister-rng')
MersenneTwister = twentyone.MersenneTwister

MAX_SEED = (1 << 16) - 1


def crypt(plaintext, seed):
    mt = MersenneTwister(seed)

    keystream = b''
    for i in range(0, len(plaintext), 4):
        keystream += mt.extract_number().to_bytes(length=4, byteorder='little')

    ciphertext = []
    for p, k in zip(plaintext, keystream):
        ciphertext.append(p ^ k)

    return bytes(ciphertext)


def crack_seed(plaintext, ciphertext):
    for seed in range(0, MAX_SEED):
        decrypted = crypt(ciphertext, seed)
        if decrypted == plaintext:
            return seed
    raise Exception  # Shouldn't occur, thanks brute force.


if __name__ == '__main__':
    seed = randint(0, MAX_SEED)
    plaintext = b'helloooAAAAAAAAAAAAAA'
    ciphertext = crypt(plaintext, seed)
    cracked_seed = crack_seed(plaintext, ciphertext)
    assert seed == cracked_seed
    print('Passed')
