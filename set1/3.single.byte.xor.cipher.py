import string

INPUT = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'


def xor(bytestring, byte):
    return bytes((b ^ byte) for b in bytestring)


def get_options(input_):
    options = []
    for digit in range(256):
        options.append(xor(bytes.fromhex(input_), digit))

    return options


def select_option(options):
    selected = None
    selected_num_ascii_letters = 0
    for option in options:
        option = option.decode('ascii', errors='ignore')
        num_ascii_letters = sum(option.count(c) for c in string.ascii_letters)
        if num_ascii_letters > selected_num_ascii_letters:
            selected = option
            selected_num_ascii_letters = num_ascii_letters

    return selected


options = get_options(INPUT)

print('Options:')
for o in options:
    print(o)

selected_option = select_option(options)

print('\nSelected Option:')
print(selected_option)
