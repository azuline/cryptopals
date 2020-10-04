"""
Break fixed-nonce CTR statistically
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from base64 import b64decode
from itertools import cycle
from secrets import token_bytes as random_bytes

from set1.c02 import xor
from set1.c03 import get_options, select_option
from set1.c06 import transpose_blocks
from set3.c18 import ctr_crypt

DATA_PATH = Path(__file__).parent / "data" / "20.txt"


def solve_ciphertexts(ciphertexts):
    ct_length, trunc_ciphertexts = truncate_ciphertexts(ciphertexts)
    transposed_cts = transpose_blocks(trunc_ciphertexts, ct_length)
    keystream = bytes(select_option(get_options(block))[0] for block in transposed_cts)
    return [xor(cycle(keystream), ct) for ct in ciphertexts]


def truncate_ciphertexts(ciphertexts):
    min_length = min(len(c) for c in ciphertexts)
    return min_length, [c[:min_length] for c in ciphertexts]


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        plaintexts = [b64decode(s) for s in fp]

    key = random_bytes(16)
    nonce = random_bytes(8)
    ciphertexts = [ctr_crypt(pt, key, nonce) for pt in plaintexts]

    print("Plaintexts:")
    for c in solve_ciphertexts(ciphertexts):
        print(c)
