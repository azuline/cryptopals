"""
The CBC padding oracle
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from random import choice
from secrets import token_bytes as random_bytes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from set2.c15 import is_padding_valid

# fmt: off
STRINGS = [
    b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=', # noqa
    b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
]
# fmt: on


def encrypt_random():
    string = choice(STRINGS)

    key = random_bytes(16)
    iv = random_bytes(16)
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    return key, iv, cipher.encrypt(pad(string, 16))


def check_ciphertext(key, iv, ciphertext):
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return is_padding_valid(plaintext)


if __name__ == "__main__":
    for _ in range(100):
        key, iv, ciphertext = encrypt_random()
        assert check_ciphertext(key, iv, ciphertext)

    print("Passed")
