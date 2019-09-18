import string

CHAR_FREQS = {
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


def xor(bytestring, byte):
    return bytes((b ^ byte) for b in bytestring)


def get_options(input_):
    options = []
    for digit in range(256):
        options.append((digit, xor(input_, digit)))

    return options


def select_option(options):
    selected_option = None
    selected_key = None
    selected_score = 0
    for digit, option in options:
        decoded = option.decode('ascii', errors='ignore')
        score = sum(CHAR_FREQS.get(o, 0) for o in decoded)
        if score > selected_score:
            selected_option = option
            selected_key = digit
            selected_score = score

    return selected_key, selected_option, selected_score


if __name__ == '__main__':
    input_ = (
        '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    )

    options = get_options(bytes.fromhex(input_))
    print('Options:')
    for o in options:
        print(o)

    selected_key, selected_option, selected_score = select_option(options)
    print(f'\nSelected key: {selected_key}')
    print('\nSelected Option:')
    print(selected_option)
    print(f'Selected score: {selected_score}')
