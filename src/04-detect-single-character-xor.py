from importlib import import_module
from itertools import chain
from pathlib import Path

three = import_module("03-single-byte-xor-cipher")

DATA_PATH = Path(__file__).parent / "challenge-data" / "4.txt"


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        strings = [bytes.fromhex(line.strip()) for line in fp]

    options = chain(*(three.get_options(str_) for str_ in strings))
    selected = three.select_option(options)

    print(f"Selected: {selected.option}")
