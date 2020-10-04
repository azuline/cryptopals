"""
Implement DH with negotiated groups, and break with malicious "g" parameters
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


def make_aes_key(integer):
    return sha1(integer.to_bytes(1600, "little"))[:16]


def diffie_hellman_mitm(g):
    # Assume p & g have been sent, acknowledged, and tampered with.

    message = b"example message~"
    print(f"DH'ing message: {message} with g = {g}")

    # Generate A's DH values.
    a = randbelow(p)
    A = pow(g, a, p)

    print("ACTION: A -> B :: Send `A`")

    # Generate B's DH values.
    b = randbelow(p)
    B = pow(g, b, p)

    print("ACTION: B -> A :: Send `B`")

    # Calculate DH shared key.
    shared_key_a = make_aes_key(pow(B, a, p))

    # Encrypt message with A's key.
    iv_a = random_bytes(16)
    cipher = AES.new(shared_key_a, mode=AES.MODE_CBC, iv=iv_a)
    message_a = cipher.encrypt(message)

    print(f"ACTION: A -> M :: Send encrypted message: {message_a}")

    if g == 1:
        broken_keys = [make_aes_key(1)]
    elif g == p:
        broken_keys = [make_aes_key(0)]
    elif g == p - 1:
        broken_keys = [make_aes_key(i) for i in [1, p - 1]]

    ciphers = [AES.new(key, mode=AES.MODE_CBC, iv=iv_a) for key in broken_keys]
    broken_messages_a = [c.decrypt(message_a) for c in ciphers]

    print(f"ACTION: M :: Decrypted A's message: {b' or '.join(broken_messages_a)}")
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

    ciphers = [AES.new(key, mode=AES.MODE_CBC, iv=iv_b) for key in broken_keys]
    broken_messages_b = [c.decrypt(message_b) for c in ciphers]

    print(f"ACTION: M :: Decrypted B's message: {b' or '.join(broken_messages_b)}")
    print(f"ACTION: M -> A :: Relay encrypted message: {message_a}")

    cipher = AES.new(shared_key_a, mode=AES.MODE_CBC, iv=iv_b)
    decrypted_message_b = cipher.decrypt(message_b)

    print(f"ACTION: A :: Decrypted B's message: {decrypted_message_b}")

    assert message in broken_messages_a
    assert message in broken_messages_b


if __name__ == "__main__":
    # If `g = 1`, then the secret key is always `1`.
    diffie_hellman_mitm(g=1)

    # If `g = p`, then the secret key is always `0`, because
    # `p^x \equiv 0 \pmod{p}` for all `x`.
    diffie_hellman_mitm(g=p)

    # If `g = p - 1`, then the secret key is always `1 or -1 \pmod{p}`, because
    # `(-1)^x \in {-1, 1}` for all `x`..
    diffie_hellman_mitm(g=p - 1)

    print("Passed")
