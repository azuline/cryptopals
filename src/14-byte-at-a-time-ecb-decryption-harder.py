import importlib
from base64 import b64decode
from secrets import token_bytes as random_bytes
from random import randint

from Crypto.Cipher import AES

eleven = importlib.import_module('11-an-ecb-cbc-detection-oracle')

# fmt: off
string = b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
""".strip())
# fmt: on


def generate_random_cipher():
    key = random_bytes(16)
    return AES.new(key, mode=AES.MODE_ECB)


def decode_string(encrypter):
    block_size = determine_block_size(encrypter)
    prefix_size = determine_prefix_size(encrypter, block_size)
    string_len = len(encrypter(b'')) - prefix_size
    decoded = b''

    for i in range(1, string_len + 1):
        input_ = b'A' * (
            block_size
            + ((block_size - prefix_size) % block_size)
            - (i % block_size)
        )
        blocks_size = len(input_) + len(decoded) + 1

        block_possibilities = {
            encrypter(input_ + decoded + bytes([b]))[
                prefix_size : prefix_size + blocks_size
            ]: bytes([b])
            for b in range(256)
        }

        decoded += block_possibilities[
            encrypter(input_)[prefix_size : prefix_size + blocks_size]
        ]

    return decoded


def determine_prefix_size(encrypter, block_size=16):
    """
    Populate encrypter so that two consecutive ECB blocks of all As are
    created. Then lower size of repeated As until two consecutive blocks are no
    longer found. That gives the prefix length.

    This could technically fail if the random bits were consecutive... but the
    odds of that happening are extremely low.
    """
    # Start with enough As to always have two consecutive blocks.
    num_as = block_size * 3

    # First find a general boundary to start decrementing at.
    ciphertext = encrypter(b'A' * num_as)
    found = set()

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        if block in found:
            # Reset i to the first occurrence of the repeated block.
            i = i - block_size
            break

        found.add(block)

    # Keep incrementing until the consecutive block contains a byte from the
    # secret string.
    block1 = ciphertext[i : i + block_size]
    block2 = ciphertext[i + block_size : i + 2 * block_size]
    while block1 == block2:
        num_as -= 1
        ciphertext = encrypter(b'A' * num_as)
        block1 = ciphertext[i : i + block_size]
        block2 = ciphertext[i + block_size : i + 2 * block_size]

    # Take the As that overflow to the left via a modulo and subtract from i.
    return i - ((num_as + 1) % block_size)


def determine_block_size(encrypter):
    resize_sizes = []
    prev_length = len(encrypter(b'A'))
    for i in range(2, 64):
        ciphertext = encrypter(b'A' * i)
        if len(ciphertext) != prev_length:
            resize_sizes.append(i)
            prev_length = len(ciphertext)
        if len(resize_sizes) == 2:
            return resize_sizes[1] - resize_sizes[0]
    raise Exception  # Won't ever happen here, perhaps with larger block size.


def pad(bytestring, boundary=16):
    return bytestring + (b'\x00' * (boundary - len(bytestring) % boundary))


if __name__ == '__main__':
    cipher = generate_random_cipher()
    prefix_size = randint(12, 36)
    prefix = random_bytes(prefix_size)
    encrypter = lambda text: cipher.encrypt(  # noqa
        pad(prefix + text + string)
    )

    assert determine_block_size(encrypter) == 16
    assert determine_prefix_size(encrypter, 16) == prefix_size

    print(decode_string(encrypter).rstrip(b'\x00').decode())
