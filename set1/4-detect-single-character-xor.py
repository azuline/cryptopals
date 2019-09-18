import importlib
from pathlib import Path

char_freqs = {
    'a': 0.08167,
    'b': 0.01492,
    'c': 0.02782,
    'd': 0.04253,
    'e': 0.12702,
    'f': 0.02228,
    'g': 0.02015,
    'h': 0.06094,
    'i': 0.06094,
    'j': 0.00153,
    'k': 0.00772,
    'l': 0.04025,
    'm': 0.02406,
    'n': 0.06749,
    'o': 0.07507,
    'p': 0.01929,
    'q': 0.00095,
    'r': 0.05987,
    's': 0.06327,
    't': 0.09056,
    'u': 0.02758,
    'v': 0.00978,
    'w': 0.02360,
    'x': 0.00150,
    'y': 0.01974,
    'z': 0.00074,
    ' ': 0.13000,
}

three = importlib.import_module('3-single-byte-xor-cipher')

with (Path(__file__).parent / '4-challenge-data.txt').open('r') as fp:
    strings = [l.strip() for l in fp]

options = {str_: three.get_options(str_) for str_ in strings}

selected_bytes = None
selected_decoded = None
selected_score = 0

for bytestr, decoded_strings in options.items():
    for str_ in decoded_strings:
        str_ = str_.decode('ascii', errors='ignore')
        score = sum(char_freqs.get(o, 0) for o in str_)
        if score > selected_score:
            selected_bytes = bytestr
            selected_decoded = str_
            selected_score = score


print('Selected:')
print(selected_bytes)
print(selected_decoded)
