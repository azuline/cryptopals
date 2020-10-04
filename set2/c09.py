"""
Implement PKCS#7 padding
"""


def pkcs7_pad(plaintext, pad_to=16):
    num = pad_to - len(plaintext) % pad_to
    return plaintext + bytes([num] * num)


if __name__ == "__main__":
    padded = pkcs7_pad(b"YELLOW SUBMARINE", pad_to=20)
    assert padded == b"YELLOW SUBMARINE\x04\x04\x04\x04"

    padded2 = pkcs7_pad(b"YELLOW SUBMARIN", pad_to=20)
    assert padded2 == b"YELLOW SUBMARIN\x05\x05\x05\x05\x05"

    print("Passed")
