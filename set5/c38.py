"""
Offline dictionary attack on simplified SRP

Not doing sockets stuff for this >_>
"""

from hashlib import pbkdf2_hmac, sha256
from hmac import compare_digest
from itertools import permutations
from math import ceil
from secrets import randbelow
from secrets import token_bytes as random_bytes

g = 2
k = 3

n = int(
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

password = b"letmein"


def run_srp_intended():
    """
    The original SRP protocol from challenge 38.
    """
    # SERVER (x, v)
    salt = random_bytes(16)
    x_serv = int.from_bytes(sha256(salt + password).digest(), "little")
    v = pow(g, x_serv, n)

    # CLIENT (I, A)
    a = randbelow(n)
    A = pow(g, a, n)

    # SERVER (B, u)
    b = randbelow(n)
    B = pow(g, b, n)
    u = int.from_bytes(random_bytes(16), "little")

    # CLIENT (x, S, K)
    x_clnt = int.from_bytes(sha256(salt + password).digest(), "little")
    S_clnt = pow(B, a + u * x_clnt, n)
    K_clnt = sha256(S_clnt.to_bytes(ceil(S_clnt.bit_length() / 8), "little")).digest()
    HMAC_clnt = pbkdf2_hmac("sha256", K_clnt, salt, 100000)

    # SERVER (S, K)
    S_serv = pow(A * pow(v, u, n), b, n)
    K_serv = sha256(S_serv.to_bytes(ceil(S_serv.bit_length() / 8), "little")).digest()
    HMAC_serv = pbkdf2_hmac("sha256", K_serv, salt, 100000)

    assert compare_digest(HMAC_clnt, HMAC_serv)
    print("Client and server digests matched.")


def run_srp_mitm():
    """
    The MITM protocol from challenge 38. Server does not know password, but wants to
    crack it using A's HMAC-SHA256.
    """
    # SERVER (x, v)
    salt = random_bytes(16)

    # CLIENT (I, A)
    a = randbelow(n)
    A = pow(g, a, n)

    # SERVER (B, u)
    b = randbelow(n)
    B = pow(g, b, n)
    u = int.from_bytes(random_bytes(16), "little")

    # CLIENT (x, S, K)
    x_clnt = int.from_bytes(sha256(salt + password).digest(), "little")
    S_clnt = pow(B, a + u * x_clnt, n)
    K_clnt = sha256(S_clnt.to_bytes(ceil(S_clnt.bit_length() / 8), "little")).digest()
    HMAC_clnt = pbkdf2_hmac("sha256", K_clnt, salt, 100000)

    # Server shouldn't have access to the following.
    del a
    del x_clnt
    del S_clnt
    del K_clnt

    # ATTACKER (Have: A, b, B, u, salt, HMAC_clnt)
    # Goal: Recover the password....... with dictionary attack.
    # wtf is this

    dictionary = ["a", "b", "c", "let", "cat", "dog", "me", "in", "out"]
    for num_words in range(1, 5):
        for perm in permutations(dictionary, r=num_words):
            cracked_password = "".join(perm).encode()

            x_mitm = int.from_bytes(sha256(salt + cracked_password).digest(), "little")
            v = pow(g, x_mitm, n)

            S_mitm = pow(A * pow(v, u, n), b, n)
            K_mitm = sha256(
                S_mitm.to_bytes(ceil(S_mitm.bit_length() / 8), "little")
            ).digest()
            HMAC_mitm = pbkdf2_hmac("sha256", K_mitm, salt, 100000)

            if compare_digest(HMAC_mitm, HMAC_clnt):
                assert password == cracked_password
                print("Password successfully cracked.")
                return

    print("Failed to crack password.")
    assert False


if __name__ == "__main__":
    run_srp_mitm()
