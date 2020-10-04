"""
Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
"""

import sys  # isort:skip
from pathlib import Path  # isort:skip

sys.path.append(str(Path(__file__).parent.resolve().parent))

from secrets import randbelow
from secrets import token_bytes as random_bytes

from Crypto.Cipher import AES

from set4.c28 import sha1

# NIST params.

p = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff",
    16,
)

g = 2


def diffie_hellman_mitm():
    message = b"example message~"
    print(f"DH'ing message: {message}")

    # Generate A's DH values.
    a = randbelow(p)
    A = pow(g, a, p)

    print("ACTION: A -> M :: Send `p, g, A`")

    A = p

    print("ACTION: M -> B :: Send `p, g, p`")

    # Generate B's DH values.
    b = randbelow(p)
    B = pow(g, b, p)

    print("ACTION: B -> M :: Send `B`")

    B = p

    print("ACTION: M -> A :: Send `p`")

    # Calculate DH shared key.
    shared_key_a = sha1(pow(B, a, p).to_bytes(1600, "little"))[:16]

    # Encrypt message with A's key.
    iv_a = random_bytes(16)
    cipher = AES.new(shared_key_a, mode=AES.MODE_CBC, iv=iv_a)
    message_a = cipher.encrypt(message)

    print(f"ACTION: A -> M :: Send encrypted message: {message_a}")

    broken_key = sha1((0).to_bytes(1600, "little"))[:16]

    cipher = AES.new(broken_key, mode=AES.MODE_CBC, iv=iv_a)
    broken_message_a = cipher.decrypt(message_a)

    print(f"ACTION: M :: Decrypted A's message: {broken_message_a}")
    print(f"ACTION: M -> B :: Relay encrypted message: {message_a}")

    # Calculate DH shared key.
    shared_key_b = sha1(pow(A, b, p).to_bytes(1600, "little"))[:16]

    # Decrypt A's message with shared key.
    cipher = AES.new(shared_key_b, mode=AES.MODE_CBC, iv=iv_a)
    decrypted_message_a = cipher.decrypt(message_a)

    print(f"ACTION: B :: Decrypted A's message: {decrypted_message_a}")

    iv_b = random_bytes(16)
    cipher = AES.new(shared_key_b, mode=AES.MODE_CBC, iv=iv_b)
    message_b = cipher.encrypt(decrypted_message_a)

    print(f"ACTION: B -> M :: Send A's encrypted message back: {message_b}")

    cipher = AES.new(broken_key, mode=AES.MODE_CBC, iv=iv_b)
    broken_message_b = cipher.decrypt(message_b)

    print(f"ACTION: M :: Decrypted B's message: {broken_message_b}")
    print(f"ACTION: M -> A :: Relay encrypted message: {message_a}")

    cipher = AES.new(shared_key_a, mode=AES.MODE_CBC, iv=iv_b)
    decrypted_message_b = cipher.decrypt(message_b)

    print(f"ACTION: A :: Decrypted B's message: {decrypted_message_b}")

    assert broken_message_a == broken_message_b == message


if __name__ == "__main__":
    # Because we replaced public keys with `p`, the key is always zero...
    diffie_hellman_mitm()

    print("Passed")
