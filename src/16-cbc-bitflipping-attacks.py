from secrets import token_bytes as random_bytes
from urllib.parse import quote

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

prefix = b"comment=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"


def wrap_string(string):
    key = random_bytes(16)
    iv = random_bytes(16)
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    uinfo = prefix + quote(string).encode() + suffix
    return key, iv, cipher.encrypt(pad(uinfo, 16))


def check_admin(key, iv, ciphertext):
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    # for i in range(0, len(plaintext), 16):
    #     print(plaintext[i : i + 16])

    return b";admin=true;" in plaintext


def break_crypto(ciphertext):
    ciphertext = list(ciphertext)
    for i, (plain, target) in enumerate(zip(b"Badmin%3Dtrue;", b";admin=true;")):
        ciphertext[i + 18] ^= plain ^ target

    return bytes(ciphertext)


if __name__ == "__main__":
    key, iv, ciphertext = wrap_string(b"-;admin=true")
    assert not check_admin(key, iv, ciphertext)
    ciphertext = break_crypto(ciphertext)
    assert check_admin(key, iv, ciphertext)
    print("Passed")
