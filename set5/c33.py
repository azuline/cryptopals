"""
Implement Diffie-Hellman
"""

from secrets import randbelow

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


def diffie_hellman():
    a = randbelow(p)
    A = pow(g, a, p)

    b = randbelow(p)
    B = pow(g, b, p)

    s_a = pow(B, a, p)
    s_b = pow(A, b, p)

    return s_a, s_b


if __name__ == "__main__":
    s_a, s_b = diffie_hellman()
    assert s_a == s_b

    print("The math checks out!")
