from importlib import import_module
from base64 import b64decode
from pathlib import Path

KEYSIZE_LIMS = [2, 40]

three = import_module("03-single-byte-xor-cipher")
five = import_module("05-implement-repeating-key-xor")


def compute_edit_distance(bstr1, bstr2):
    diff = [a ^ b for a, b, in zip(bstr1, bstr2)]

    edit_distance = 0
    for byte in diff:
        edit_distance += sum(bit.count("1") for bit in bin(byte))

    return edit_distance


def find_keysize(data, lower_limit, upper_limit):
    keysizes = []
    for size in range(lower_limit, upper_limit):
        average_total = []
        for i in range(0, len(data), size):
            edit_dist = compute_edit_distance(
                data[i : i + size], data[i + size : i + 2 * size]
            )
            average_total.append(edit_dist / (size or 1))
        keysizes.append((sum(average_total) / (len(data) / size), size))

    return sorted(keysizes, key=lambda tup: tup[0])[0][1]


def break_ciphertext(data, keysize):
    blocks = []
    while data:
        blocks.append(data[:keysize])
        data = data[keysize:]
    return blocks


def transpose_blocks(blocks, keysize):
    transposed = []
    for i in range(keysize):
        tblock = b""
        for block in blocks:
            try:
                tblock += bytes([block[i]])
            except IndexError:
                pass
        transposed.append(tblock)
    return transposed


if __name__ == "__main__":
    with (Path(__file__).parent / "challenge-data" / "6.txt").open("r") as fp:
        encrypted_data = b64decode(fp.read())

    assert compute_edit_distance(b"this is a test", b"wokka wokka!!!") == 37

    keysize = find_keysize(encrypted_data, *KEYSIZE_LIMS)
    blocks = break_ciphertext(encrypted_data, keysize)
    transposed_blocks = transpose_blocks(blocks, keysize)
    key = b""
    for block in transposed_blocks:
        options = three.get_options(block)
        key += bytes([three.select_option(options)[0]])

    print("Key:")
    print(key)
    print("\nDecrypted:")
    print(five.encrypt(encrypted_data, key).decode())
