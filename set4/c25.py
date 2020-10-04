"""
Break "random access read/write" AES CTR
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from base64 import b64decode
from random import randint
from secrets import token_bytes

from Crypto.Cipher import AES

from set1.c07 import DATA_PATH
from set3.c18 import ctr_crypt, get_keystream


def get_plaintext():
    cipher = AES.new(b"YELLOW SUBMARINE", mode=AES.MODE_ECB)
    with DATA_PATH.open("r") as fp:
        return cipher.decrypt(b64decode(fp.read()))


def encrypt(plaintext):
    key = token_bytes(16)
    nonce = randint(0, 127).to_bytes(8, "little")
    return key, nonce, ctr_crypt(plaintext, key, nonce)


def edit(ciphertext, key, nonce, offset, newtext):
    keystream = get_keystream(key, nonce, len(ciphertext))

    ciphertext = list(ciphertext)
    for i in range(len(newtext)):
        ciphertext[i + offset] = newtext[i] ^ keystream[i + offset]

    return ciphertext


def recover_plaintext(ciphertext, edit_function):
    newtext = b"A" * len(ciphertext)
    newtext_xor = edit_function(ciphertext, 0, newtext)
    keystream = bytes([n ^ x for n, x in zip(newtext, newtext_xor)])
    return bytes([c ^ k for c, k in zip(ciphertext, keystream)])


if __name__ == "__main__":
    plaintext = get_plaintext()
    key, nonce, ciphertext = encrypt(plaintext)
    edit_function = lambda ciphertext, offset, newtext: edit(  # noqa
        ciphertext, key, nonce, offset, newtext
    )
    assert recover_plaintext(ciphertext, edit_function) == plaintext
    print("Passed")
