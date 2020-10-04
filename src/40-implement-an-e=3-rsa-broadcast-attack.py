from collections import namedtuple
from importlib import import_module
from math import prod

from Crypto.Util.number import getPrime

thirtynine = import_module("39-implement-rsa")

Pubkey = namedtuple("Pubkey", ["n", "e"])

e = 3

message = int(b"attack at dawn".hex(), 16)


def gen_keypair():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q

    pub = Pubkey(n, e)

    return pub


def get_encrypted_message(pubkey):
    return pow(message, e, pubkey.n)


def cube_root(integer):
    # Run a binary search from 2 to integer looking for the cube root.
    lower = 2
    upper = integer

    while lower < upper:
        middle = (upper + lower) // 2
        third_root = middle ** 3

        if third_root == integer:
            return middle
        elif third_root > integer:
            upper = middle
        else:
            lower = middle

    raise Exception(f"{integer} has no third root.")


def run_crt(ciphertexts):
    N = prod(n for _, n in ciphertexts)
    result = 0

    for ct, n in ciphertexts:
        b = N // n
        result += ct * b * thirtynine.invmod(b, n)

    return result % N


def run_attack():
    pubkeys = [gen_keypair() for _ in range(3)]

    ciphertexts = [(get_encrypted_message(pub), pub.n) for pub in pubkeys]

    result = run_crt(ciphertexts)
    cracked_message = cube_root(result)

    assert message == cracked_message
    print("Attack successful!")


if __name__ == "__main__":
    assert 3 == cube_root(27)
    assert 39 == run_crt([(0, 3), (3, 4), (4, 5)])

    run_attack()
