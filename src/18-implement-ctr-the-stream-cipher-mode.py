from base64 import b64decode
from Crypto.Cipher import AES


def ctr_crypt(text, key, nonce):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    counter = 0

    keystream = b''
    for i in range(0, len(text), 16):
        keystream += cipher.encrypt(
            nonce.to_bytes(length=8, byteorder='little')
            + counter.to_bytes(length=8, byteorder='little')
        )
        counter += 1

    output = []
    for c, k in zip(text, keystream):
        output.append(c ^ k)

    return bytes(output)


if __name__ == '__main__':
    ciphertext = b64decode(
        b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    )
    key = b'YELLOW SUBMARINE'
    nonce = 0
    print(ctr_crypt(ciphertext, key, nonce))
