from pathlib import Path


def find_aes_in_ecb(ciphertexts):
    occurrences = [(get_repeated_block_count(ct), ct) for ct in ciphertexts]
    return sorted(occurrences, key=lambda tup: tup[0], reverse=True)[0][1]


def get_repeated_block_count(cipher):
    repeated = 0
    found = set()

    for i in range(0, len(cipher), 16):
        block = cipher[i : i + 16]

        if block in found:
            repeated += 1
        else:
            found.add(block)

    return repeated


if __name__ == "__main__":
    with (Path(__file__).parent / "challenge-data" / "8.txt").open("r") as fp:
        ciphertexts = [bytes.fromhex(line) for line in fp]

    print(find_aes_in_ecb(ciphertexts).hex())
