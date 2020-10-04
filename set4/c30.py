"""
Break an MD4 keyed MAC using length extension
"""

# Implementation of MD4 taken and modified from
# https://gist.github.com/BenWiederhake/eb6dfc2c31d3dc8c34508f4fd091cea9

import math
import struct


def leftrotate(i, n):
    return ((i << n) & 0xFFFFFFFF) | (i >> (32 - n))


def F(x, y, z):
    return (x & y) | (~x & z)


def G(x, y, z):
    return (x & y) | (x & z) | (y & z)


def H(x, y, z):
    return x ^ y ^ z


class Md4Hash(object):
    def __init__(
        self, digest_vars=(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476), count=0,
    ):
        self.remainder = b""
        self.count = count
        self.h = list(digest_vars)

    def _add_chunk(self, chunk):
        self.count += 1
        X = list(struct.unpack("<16I", chunk) + (None,) * (80 - 16))
        h = [x for x in self.h]
        # Round 1
        s = (3, 7, 11, 19)
        for r in range(16):
            i = (16 - r) % 4
            k = r
            h[i] = leftrotate(
                (h[i] + F(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4]) + X[k])
                % 2 ** 32,
                s[r % 4],
            )
        # Round 2
        s = (3, 5, 9, 13)
        for r in range(16):
            i = (16 - r) % 4
            k = 4 * (r % 4) + r // 4
            h[i] = leftrotate(
                (
                    h[i]
                    + G(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4])
                    + X[k]
                    + 0x5A827999
                )
                % 2 ** 32,
                s[r % 4],
            )
        # Round 3
        s = (3, 9, 11, 15)
        k = (
            0,
            8,
            4,
            12,
            2,
            10,
            6,
            14,
            1,
            9,
            5,
            13,
            3,
            11,
            7,
            15,
        )  # wish I could function
        for r in range(16):
            i = (16 - r) % 4
            h[i] = leftrotate(
                (
                    h[i]
                    + H(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4])
                    + X[k[r]]
                    + 0x6ED9EBA1
                )
                % 2 ** 32,
                s[r % 4],
            )

        for i, v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2 ** 32

    def update(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b""
        for chunk in range(0, len(message) - r, 64):
            self._add_chunk(message[chunk : chunk + 64])
        return self

    def digest(self):
        le = len(self.remainder) + 64 * self.count
        self.update(b"\x80" + b"\x00" * ((55 - le) % 64) + struct.pack("<Q", le * 8))
        out = struct.pack("<4I", *self.h)
        return out


def md4(data, key=b""):
    return Md4Hash().update(key + data).digest()


# End of MD4 code.


def md_pad(message, keylen):
    message_len = len(message) + keylen
    message += b"\x80" + b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    message += struct.pack(b"<Q", message_len * 8)
    return message


def modify_admin(string, prefix_hash, keylen):
    admin_str = b";admin=true"
    modified_string = md_pad(string, keylen) + admin_str

    h0 = struct.unpack("<I", prefix_hash[0:4])[0]
    h1 = struct.unpack("<I", prefix_hash[4:8])[0]
    h2 = struct.unpack("<I", prefix_hash[8:12])[0]
    h3 = struct.unpack("<I", prefix_hash[12:16])[0]

    modified_count = int(math.ceil((len(modified_string) - len(admin_str)) / 64))

    modified_hash = (
        Md4Hash(digest_vars=(h0, h1, h2, h3), count=modified_count)
        .update(admin_str)
        .digest()
    )

    return modified_string, modified_hash


if __name__ == "__main__":
    secret_key = b"luminously"
    string = (
        b"comment1=cooking%20MCs;userdata=foo;"
        b"comment2=%20like%20a%20pound%20of%20bacon"
    )

    prefix_hash = md4(string, key=secret_key)

    modified_string, modified_hash = modify_admin(string, prefix_hash, len(secret_key))
    expected_hash = md4(modified_string, key=secret_key)

    print("\nModified string:")
    print(modified_string)
    print("\nModified hash:")
    print(modified_hash)
    print("\nExpected hash:")
    print(expected_hash)

    assert modified_hash == expected_hash

    print("\nPassed")
