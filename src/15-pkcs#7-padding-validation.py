def is_padding_valid(bytestring):
    last_byte = bytestring[-1]
    num_bytes = last_byte
    return all(last_byte == bytestring[-1 * i] for i in range(1, num_bytes + 1))


if __name__ == "__main__":
    assert is_padding_valid(b"ICE ICE BABY\x04\x04\x04\x04")
    assert not is_padding_valid(b"ICE ICE BABY\x05\x05\x05\x05")
    assert not is_padding_valid(b"ICE ICE BABY\x01\x02\x03\x04")
    print("Passed")
