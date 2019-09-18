def pkcs7_pad(plaintext, pad_to=16):
    return plaintext + '\x04' * (pad_to - len(plaintext) % pad_to)


if __name__ == '__main__':
    padded = pkcs7_pad('YELLOW SUBMARINE', pad_to=20)
    assert padded == 'YELLOW SUBMARINE\x04\x04\x04\x04'
    print('Passed')
