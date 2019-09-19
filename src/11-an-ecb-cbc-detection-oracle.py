from importlib import import_module
from random import randint
from secrets import token_bytes as random_bytes

from Crypto.Cipher import AES

nine = import_module('09-implement-pkcs#7-padding')


def get_padding():
    return random_bytes(randint(5, 10))


def get_random_cipher():
    key = random_bytes(16)
    if randint(0, 1):
        return AES.MODE_ECB, AES.new(key, mode=AES.MODE_ECB)
    return AES.MODE_CBC, AES.new(key, mode=AES.MODE_CBC, iv=random_bytes(16))


def encrypt_plaintext(cipher, plaintext):
    return cipher.encrypt(
        nine.pkcs7_pad(get_padding() + plaintext + get_padding())
    )


def guess_mode(cipher):
    encrypted = encrypt_plaintext(cipher, b'a' * 256)
    found = set()
    for i in range(0, len(encrypted), 16):
        block = encrypted[i : i + 16]
        if block in found:
            return AES.MODE_ECB
        found.add(block)
    return AES.MODE_CBC


if __name__ == '__main__':
    for _ in range(10):
        mode, cipher = get_random_cipher()
        guess = guess_mode(cipher)
        assert mode == guess
    print('Passed')
