"""
Implement CBC mode
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from base64 import b64decode

from Crypto.Cipher import AES

from set1.c02 import xor
from set2.c09 import pkcs7_pad

DATA_PATH = Path(__file__).parent / "data" / "10.txt"


def cbc_encrypt(plaintext, key, iv=(b"\x00" * 16)):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    ciphertext = b""
    prevblock = iv

    for i in range(0, len(plaintext), 16):
        plainblock = pkcs7_pad(plaintext[i : i + 16])
        cipherblock = cipher.encrypt(xor(prevblock, plainblock))

        ciphertext += cipherblock
        prevblock = cipherblock

    return ciphertext


def cbc_decrypt(ciphertext, key, iv=(b"\x00" * 16)):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    plaintext = b""
    prevblock = iv

    for i in range(0, len(ciphertext), 16):
        cipherblock = ciphertext[i : i + 16]
        plainblock = xor(cipher.decrypt(cipherblock), prevblock)

        plaintext += plainblock
        prevblock = cipherblock

    return plaintext


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        encrypted_data = b64decode(fp.read())

    print(cbc_decrypt(encrypted_data, b"YELLOW SUBMARINE").decode())
