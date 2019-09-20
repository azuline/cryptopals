from base64 import b64decode
from importlib import import_module
from pathlib import Path

three = import_module('03-single-byte-xor-cipher')
six = import_module('06-break-repeating-key')


def solve_ciphertexts(ciphertexts):
    ct_length, ciphertexts = truncate_ciphertexts(ciphertexts)
    transposed_cts = six.transpose_blocks(ciphertexts, ct_length)

    keystream = b''
    for block in transposed_cts:
        options = three.get_options(block)
        keystream += bytes([three.select_option(options)[0]])

    plaintexts = []
    for ct in ciphertexts:
        pt = []
        for b1, b2 in zip(keystream, ct):
            pt.append(b1 ^ b2)
        plaintexts.append(bytes(pt))

    return plaintexts


def truncate_ciphertexts(ciphertexts):
    min_length = min(len(c) for c in ciphertexts)
    return min_length, [c[:min_length] for c in ciphertexts]


if __name__ == '__main__':
    with (Path(__file__).parent / 'challenge-data' / '20.txt').open('r') as fp:
        ciphertexts = [b64decode(s) for s in fp]

    print('Plaintexts:')
    for c in solve_ciphertexts(ciphertexts):
        print(c)
