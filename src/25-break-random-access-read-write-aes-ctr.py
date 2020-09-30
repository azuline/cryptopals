from base64 import b64decode
from importlib import import_module
from pathlib import Path
from random import randint
from secrets import token_bytes

from Crypto.Cipher import AES

eighteen = import_module("18-implement-ctr-the-stream-cipher-mode")


def get_plaintext():
    cipher = AES.new(b"YELLOW SUBMARINE", mode=AES.MODE_ECB)
    with (Path(__file__).parent / "challenge-data" / "7.txt").open("r") as fp:
        return cipher.decrypt(b64decode(fp.read()))


def encrypt(plaintext):
    key = token_bytes(16)
    nonce = randint(0, 127)
    return key, nonce, eighteen.ctr_crypt(plaintext, key, nonce)


def edit(ciphertext, key, nonce, offset, newtext):
    keystream = eighteen.get_keystream(key, nonce, len(ciphertext))

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
