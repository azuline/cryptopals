from importlib import import_module
from random import randint
from secrets import token_bytes
from urllib.parse import quote

eighteen = import_module('18-implement-ctr-the-stream-cipher-mode')


prefix = b'comment=cooking%20MCs;userdata='
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'


def wrap_string(string):
    key = token_bytes(16)
    nonce = randint(0, 127)
    uinfo = prefix + quote(string).encode() + suffix
    ciphertext = eighteen.ctr_crypt(uinfo, key, nonce)
    return key, nonce, ciphertext


def check_admin(key, nonce, ciphertext):
    plaintext = eighteen.ctr_crypt(ciphertext, key, nonce)
    # print(plaintext)
    return b';admin=true;' in plaintext


def break_crypto(ciphertext):
    ciphertext = list(ciphertext)
    for i, (plain, target) in enumerate(
        zip(b'Badmin%3Dtrue;', b';admin=true;')
    ):
        ciphertext[i + 34] ^= plain ^ target

    return bytes(ciphertext)


if __name__ == '__main__':
    key, nonce, ciphertext = wrap_string(b'-;admin=true')
    assert not check_admin(key, nonce, ciphertext)
    ciphertext = break_crypto(ciphertext)
    assert check_admin(key, nonce, ciphertext)
    print('Passed')
