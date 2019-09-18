INPUT = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

OUTPUT = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


def encrypt(input_, key):
    key = [ord(c) for c in key]
    output = b''
    index = 0
    for c in input_:
        output += bytes([ord(c) ^ key[index]])
        index = 0 if index == len(key) - 1 else index + 1

    return output.hex()


assert encrypt(INPUT, 'ICE') == OUTPUT
print('Passed')
