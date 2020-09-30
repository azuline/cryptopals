from base64 import b64decode
from importlib import import_module
from pathlib import Path

from Crypto.Cipher import AES

two = import_module("02-fixed-xor")
nine = import_module("09-implement-pkcs#7-padding")


def cbc_encrypt(plaintext, key, iv=(b"\x00" * 16)):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    ciphertext = b""
    prevblock = iv

    for i in range(0, len(plaintext), 16):
        plainblock = nine.pkcs7_pad(plaintext[i : i + 16])
        cipherblock = cipher.encrypt(two.xor(prevblock, plainblock))

        ciphertext += cipherblock
        prevblock = cipherblock

    return ciphertext


def cbc_decrypt(ciphertext, key, iv=(b"\x00" * 16)):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    plaintext = b""
    prevblock = iv

    for i in range(0, len(ciphertext), 16):
        cipherblock = ciphertext[i : i + 16]
        plainblock = two.xor(cipher.decrypt(cipherblock), prevblock)

        plaintext += plainblock
        prevblock = cipherblock

    return plaintext


if __name__ == "__main__":
    with (Path(__file__).parent / "challenge-data" / "10.txt").open("r") as fp:
        encrypted_data = b64decode(fp.read())

    print(cbc_decrypt(encrypted_data, b"YELLOW SUBMARINE").decode())
