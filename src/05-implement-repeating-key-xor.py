from itertools import cycle


def encrypt(input_, key):
    return bytes(c ^ k for c, k in zip(input_, cycle(key)))


if __name__ == "__main__":
    input_ = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"  # noqa

    output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"  # noqa

    assert encrypt(input_.encode(), b"ICE").hex() == output

    print("Passed")
