"""
AES in ECB mode
"""

from base64 import b64decode
from pathlib import Path

from Crypto.Cipher import AES

DATA_PATH = Path(__file__).parent / "data" / "07.txt"


def ecb_decrypt(data, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.decrypt(data)


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        encrypted_data = b64decode(fp.read())

    key = b"YELLOW SUBMARINE"

    print(ecb_decrypt(encrypted_data, key).decode())
