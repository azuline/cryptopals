"""
Implement CTR, the stream cipher mode
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from base64 import b64decode

from Crypto.Cipher import AES

from set1.c02 import xor


def ctr_crypt(text, key, nonce):
    return xor(text, get_keystream(key, nonce, len(text)))


def get_keystream(key, nonce, length):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    keystream = b""
    counter = 0

    for _ in range(0, length, 16):
        keystream += cipher.encrypt(nonce + counter.to_bytes(8, "little"))
        counter += 1

    return keystream


if __name__ == "__main__":
    ciphertext = b64decode(
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    key = b"YELLOW SUBMARINE"
    nonce = (0).to_bytes(8, "little")
    print(ctr_crypt(ciphertext, key, nonce))
