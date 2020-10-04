from Crypto.Util.number import getPrime


def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)


def invmod(integer, modulo):
    _, x, _ = extended_gcd(integer, modulo)
    return x % modulo


def run_rsa():
    # Generate 2 random primes. We'll use small numbers to start, so you can just pick
    # them out of a prime table. Call them "p" and "q".
    p = getPrime(1024)
    q = getPrime(1024)

    # Let n be p * q. Your RSA math is modulo n.
    n = p * q

    # Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
    et = (p - 1) * (q - 1)

    # Let e be 3.
    e = 3

    # Compute d = invmod(e, et). invmod(17, 3120) is 2753.
    d = invmod(e, et)

    # Your public key is [e, n]. Your private key is [d, n].

    # To encrypt: c = m**e%n. To decrypt: m = c**d%n
    # Test this out with a number, like "42".
    message = 420420

    ciphertext = pow(message, e, n)
    plaintext = pow(ciphertext, d, n)

    assert message == plaintext
    print("RSA encryption & decryption succeeded.")


if __name__ == "__main__":
    assert invmod(17, 3120) == 2753

    run_rsa()
