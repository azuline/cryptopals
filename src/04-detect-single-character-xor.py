from importlib import import_module
from pathlib import Path

three = import_module("03-single-byte-xor-cipher")


if __name__ == "__main__":
    with (Path(__file__).parent / "challenge-data" / "4.txt").open("r") as fp:
        strings = [bytes.fromhex(line.strip()) for line in fp]

    options = [(str_, three.select_option(three.get_options(str_))) for str_ in strings]

    selected = sorted(options, key=lambda o: o[1][2], reverse=True)[0][1]

    print(f"Selected: {selected[1]}")
