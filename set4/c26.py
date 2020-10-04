"""
CTR bitflipping
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from random import randint
from secrets import token_bytes
from urllib.parse import quote

from set3.c18 import ctr_crypt

prefix = b"comment=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"


def wrap_string(string):
    key = token_bytes(16)
    nonce = randint(0, 127).to_bytes(8, "little")
    uinfo = prefix + quote(string).encode() + suffix
    ciphertext = ctr_crypt(uinfo, key, nonce)
    return key, nonce, ciphertext


def check_admin(key, nonce, ciphertext):
    plaintext = ctr_crypt(ciphertext, key, nonce)
    # print(plaintext)
    return b";admin=true;" in plaintext


def break_crypto(ciphertext):
    ciphertext = list(ciphertext)
    for i, (plain, target) in enumerate(zip(b"Badmin%3Dtrue;", b";admin=true;")):
        ciphertext[i + 34] ^= plain ^ target

    return bytes(ciphertext)


if __name__ == "__main__":
    key, nonce, ciphertext = wrap_string(b"-;admin=true")
    assert not check_admin(key, nonce, ciphertext)

    ciphertext = break_crypto(ciphertext)
    assert check_admin(key, nonce, ciphertext)

    print("Passed")
