"""
Detect single-character XOR
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from itertools import chain

from set1.c03 import get_options, select_option

DATA_PATH = Path(__file__).parent / "data" / "04.txt"


if __name__ == "__main__":
    with DATA_PATH.open("r") as fp:
        strings = [bytes.fromhex(line.strip()) for line in fp]

    options = chain(*(get_options(str_) for str_ in strings))
    selected = select_option(options)

    print(f"Selected: {selected.option}")
