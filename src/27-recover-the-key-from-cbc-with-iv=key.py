from secrets import token_bytes as random_bytes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class InvalidASCII(Exception):
    pass


def encrypt(string):
    key_iv = random_bytes(16)
    cipher = AES.new(key_iv, mode=AES.MODE_CBC, iv=key_iv)
    return key_iv, cipher.encrypt(pad(string, 16))


def decrypt(key_iv, ciphertext):
    cipher = AES.new(key_iv, mode=AES.MODE_CBC, iv=key_iv)
    plaintext = cipher.decrypt(ciphertext)
    verify_ascii(plaintext)
    return plaintext


def verify_ascii(plaintext):
    try:
        plaintext.decode('ascii')
    except UnicodeDecodeError:
        raise InvalidASCII(plaintext)


def extract_key(ciphertext, decrypter):
    ciphertext = list(ciphertext)
    ciphertext[16:32] = [0] * 16
    ciphertext = bytes(ciphertext)

    try:
        decrypter(ciphertext)
    except InvalidASCII as e:
        plaintext = e.args[0]

    key = bytes([a ^ b for a, b in zip(plaintext[:16], plaintext[32:48])])
    return key


if __name__ == '__main__':
    plaintext = (
        b'mean white cow power might strong pair sentence hat quiet hair'
    )
    key_iv, ciphertext = encrypt(plaintext)
    assert key_iv == extract_key(
        ciphertext, lambda ciphertext: decrypt(key_iv, ciphertext)
    )
    print('Passed')
