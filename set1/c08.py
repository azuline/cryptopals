"""
Detect AES in ECB mode
"""

from collections import Counter
from pathlib import Path

DATA_PATH = Path(__file__).parent / "data" / "08.txt"


def find_aes_in_ecb(ciphertexts):
    return max(ciphertexts, key=get_repeated_block_count)


def get_repeated_block_count(cipher):
    blocks = [cipher[i : i + 16] for i in range(0, len(cipher), 16)]
    return sum(v - 1 for v in Counter(blocks).values())


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        ciphertexts = [bytes.fromhex(line) for line in fp]

    print(find_aes_in_ecb(ciphertexts).hex())
