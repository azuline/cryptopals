"""
Byte-at-a-time ECB decryption (Simple)
"""

from base64 import b64decode
from secrets import token_bytes as random_bytes

from Crypto.Cipher import AES

# fmt: off
string = b64decode("""\
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
# fmt: on


def generate_random_cipher():
    key = random_bytes(16)
    return AES.new(key, mode=AES.MODE_ECB)


def decode_string(encrypter):
    string_len = len(encrypter(b""))
    block_size = determine_block_size(encrypter)
    decoded = b""

    for i in range(1, string_len + 1):
        input_ = b"A" * (block_size - (i % block_size))
        blocks_size = len(input_) + len(decoded) + 1
        block_possibilities = {
            encrypter(input_ + decoded + bytes([b]))[:blocks_size]: bytes([b])
            for b in range(256)
        }
        decoded += block_possibilities[encrypter(input_)[:blocks_size]]

    return decoded


def determine_block_size(encrypter):
    resize_sizes = []
    prev_length = len(encrypter(b"A"))

    for i in range(2, 64):
        ciphertext = encrypter(b"A" * i)

        if len(ciphertext) != prev_length:
            resize_sizes.append(i)
            prev_length = len(ciphertext)

        if len(resize_sizes) == 2:
            return resize_sizes[1] - resize_sizes[0]


def pad(bytestring, boundary=16):
    return bytestring + (b"\x00" * (boundary - len(bytestring) % boundary))


if __name__ == "__main__":
    cipher = generate_random_cipher()
    encrypter = lambda text: cipher.encrypt(pad(text + string))  # noqa
    assert determine_block_size(encrypter) == 16

    print(decode_string(encrypter).rstrip(b"\x00").decode())
