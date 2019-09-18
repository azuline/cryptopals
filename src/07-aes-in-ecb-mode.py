import base64
from pathlib import Path

from Crypto.Cipher import AES


def decrypt(data, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.decrypt(data)


if __name__ == '__main__':
    with (Path(__file__).parent / 'challenge-data' / '7.txt').open('r') as fp:
        encrypted_data = base64.b64decode(fp.read())

    key = b'YELLOW SUBMARINE'

    print(decrypt(encrypted_data, key).decode())
