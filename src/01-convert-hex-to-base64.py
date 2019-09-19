from base64 import b64encode


def convert(input_):
    bytes_ = bytes.fromhex(input_)
    return b64encode(bytes_)


if __name__ == '__main__':
    input_ = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'  # noqa
    output = (
        b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    )
    assert convert(input_) == output
    print('Passed')
