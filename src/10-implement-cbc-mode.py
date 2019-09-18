import importlib
from pathlib import Path

from Cipher.Crypto import AES

two = importlib.import_module('02-fixed-xor')
nine = importlib.import_module('09-implement-pkcs#7-padding')


def cbc_encrypt(plaintext, key, iv):
    ciphertext = iv
    cipher = AES.new(key, mode=AES.MODE_ECB)
    for i in range(0, len(plaintext), 16):
        ciphertext = cipher.encrypt(
            ciphertext + nine.pkcs7_pad(plaintext[i : i + 16])
        )
    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    # I dunno!
    pass


if __name__ == '__main__':
    iv = b'\x00' * 16
    with (Path(__file__).parent / 'challenge-data' / '10.txt').open('r') as fp:
        encrypted_data = fp.read()
