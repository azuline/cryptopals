INPUT = '1c0111001f010100061a024b53535009181c'
XOR_AGAINST = '686974207468652062756c6c277320657965'
OUTPUT = '746865206b696420646f6e277420706c6179'


def xor(b1, b2):
    return bytes((a ^ b) for a, b in zip(b1, b2))


def produce(input_, xor_against):
    bytes_ = bytes.fromhex(input_)
    bytes_against = bytes.fromhex(xor_against)
    return xor(bytes_, bytes_against).hex()


assert produce(INPUT, XOR_AGAINST) == OUTPUT
print('Passed')
