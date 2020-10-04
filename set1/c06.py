"""
Break repeating-key XOR
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from base64 import b64decode

from set1.c03 import get_options, select_option
from set1.c05 import encrypt

DATA_PATH = Path(__file__).parent / "data" / "06.txt"
KEYSIZE_LIMS = [2, 40]


def compute_edit_distance(bstr1, bstr2):
    diff = [a ^ b for a, b, in zip(bstr1, bstr2)]
    return sum(bin(byte).count("1") for byte in diff)


def find_keysize(data, lower_limit, upper_limit):
    def calc_total_edit_distance(size):
        blocks = break_ciphertext(data, size)
        return sum(
            compute_edit_distance(blocks[i], blocks[i + 1])
            for i in range(0, len(blocks) - 1)
        )

    return min(range(lower_limit, upper_limit), key=calc_total_edit_distance)


def break_ciphertext(data, keysize):
    return [data[i : i + keysize] for i in range(0, len(data), keysize)]


def transpose_blocks(blocks, keysize):
    return [bytes(bl[i] for bl in blocks if len(bl) > i) for i in range(keysize)]


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        encrypted_data = b64decode(fp.read())

    assert compute_edit_distance(b"this is a test", b"wokka wokka!!!") == 37

    keysize = find_keysize(encrypted_data, *KEYSIZE_LIMS)
    blocks = break_ciphertext(encrypted_data, keysize)
    transposed_blocks = transpose_blocks(blocks, keysize)

    key = bytes(select_option(get_options(block)).key for block in transposed_blocks)

    print("Key:")
    print(key)
    print("\nDecrypted:")
    print(encrypt(encrypted_data, key).decode())
