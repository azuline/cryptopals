"""
Break a SHA-1 keyed MAC using length extension
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

import math
import struct

from set4.c28 import Sha1Hash, sha1


def md_pad(message, keylen):
    message_len = len(message) + keylen
    message += b"\x80" + b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    message += struct.pack(b">Q", message_len * 8)
    return message


def modify_admin(string, prefix_hash, keylen):
    admin_str = b";admin=true"
    modified_string = md_pad(string, keylen) + admin_str

    h0 = struct.unpack(">I", prefix_hash[0:4])[0]
    h1 = struct.unpack(">I", prefix_hash[4:8])[0]
    h2 = struct.unpack(">I", prefix_hash[8:12])[0]
    h3 = struct.unpack(">I", prefix_hash[12:16])[0]
    h4 = struct.unpack(">I", prefix_hash[16:20])[0]

    modified_message_byte_len = (
        int(math.ceil((len(modified_string) - len(admin_str)) / 64)) * 64
    )

    modified_hash = (
        Sha1Hash(
            digest_vars=(h0, h1, h2, h3, h4), message_byte_len=modified_message_byte_len,
        )
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

    prefix_hash = sha1(string, key=secret_key)

    modified_string, modified_hash = modify_admin(string, prefix_hash, len(secret_key))
    expected_hash = sha1(modified_string, key=secret_key)

    print("\nModified string:")
    print(modified_string)
    print("\nModified hash:")
    print(modified_hash)
    print("\nExpected hash:")
    print(expected_hash)

    assert modified_hash == expected_hash

    print("\nPassed")
