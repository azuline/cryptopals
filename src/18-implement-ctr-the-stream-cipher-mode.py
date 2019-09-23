from base64 import b64decode

from Crypto.Cipher import AES


def ctr_crypt(text, key, nonce):
    keystream = get_keystream(key, nonce, len(text))

    output = []
    for c, k in zip(text, keystream):
        output.append(c ^ k)

    return bytes(output)


def get_keystream(key, nonce, length):
    cipher = AES.new(key, mode=AES.MODE_ECB)

    keystream = b''

    counter = 0
    for i in range(0, length, 16):
        keystream += cipher.encrypt(
            nonce.to_bytes(length=8, byteorder='little')
            + counter.to_bytes(length=8, byteorder='little')
        )
        counter += 1

    return keystream


if __name__ == '__main__':
    ciphertext = b64decode(
        b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    )
    key = b'YELLOW SUBMARINE'
    nonce = 0
    print(ctr_crypt(ciphertext, key, nonce))
