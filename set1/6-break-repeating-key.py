import base64
import importlib
from pathlib import Path

KEYSIZE_LIMS = [2, 40]

three = importlib.import_module('3-single-byte-xor-cipher')
five = importlib.import_module('5-implement-repeating-key-xor')

with (Path(__file__).parent / 'challenge-data' / '6.txt').open('r') as fp:
    encrypted_data = base64.b64decode(fp.read())


def compute_edit_distance(bstr1, bstr2):
    diff = [a ^ b for a, b, in zip(bstr1, bstr2)]

    edit_distance = 0
    for byte in diff:
        for bit in bin(byte):
            edit_distance += bit.count('1')

    return edit_distance


assert compute_edit_distance(b'this is a test', b'wokka wokka!!!') == 37


def find_keysize(data, lower_limit, upper_limit):
    selected_size = None
    smallest_edit_distance = None
    for size in range(lower_limit, upper_limit):
        first = data[:size]
        second = data[size : size * 2]
        edit_distance = compute_edit_distance(first, second) / size or 1
        if (
            not smallest_edit_distance
            or edit_distance < smallest_edit_distance
        ):
            selected_size = size
            smallest_edit_distance = edit_distance

    return selected_size


def break_ciphertext(data, keysize):
    blocks = []
    for size in range(1, keysize):
        datacopy = bytes(data)
        while datacopy:
            blocks.append(datacopy[:keysize])
            datacopy = datacopy[keysize:]
    return blocks


def transpose_blocks(blocks, keysize):
    transposed = []
    for i in range(keysize):
        tblock = b''
        for block in blocks:
            try:
                tblock += bytes([block[i]])
            except IndexError:
                pass
        transposed.append(tblock)
    return transposed


if __name__ == '__main__':
    keysize = find_keysize(encrypted_data, *KEYSIZE_LIMS)
    blocks = break_ciphertext(encrypted_data, keysize)
    transposed_blocks = transpose_blocks(blocks, keysize)
    key = b''
    for block in transposed_blocks:
        options = three.get_options(block)
        key += bytes([three.select_option(options)[0]])

    print('Key:')
    print(key)
    print('Decrypted:')
    print(five.encrypt(encrypted_data, key))
