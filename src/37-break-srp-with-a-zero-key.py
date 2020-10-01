"""
Start the server and execute client!
"""

import socket
from hashlib import pbkdf2_hmac, sha256
from importlib import import_module

thirtysix = import_module("36-implement-secure-remote-password-srp")

PORT = 34443

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


def run_client(A):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", PORT))

    print("Client: Connected to server socket")

    # Send I, A=g**a % N (a la Diffie Hellman)

    print("Client: Sending A to server")

    sock.send(A.to_bytes(1600, "little"))

    # Receive salt, B=kv + g**b % N

    print("Client: Receiving salt, B from server")

    salt = sock.recv(16)
    _ = int.from_bytes(sock.recv(1600), "little")

    # Generate string xH=SHA256(salt|password)
    # Convert xH to integer x somehow (put 0x on hexdigest)
    # Generate S = (B - k * g**x)**(a + u * x) % N
    # Generate K = SHA256(S)

    print("Client: Calculating x, S, K")

    S = 0
    K = sha256(S.to_bytes(1600, "little")).digest()

    # Send HMAC-SHA256(K, salt)

    print("Client: Calculating and sending HMAC to server")

    hmac = pbkdf2_hmac("sha256", K, salt, 100000)
    sock.send(hmac)

    # Receive "OK" if HMAC-SHA256(K, salt) validates

    okay = sock.recv(16).decode()

    print(f"Client: Received {okay} from server")

    assert okay == "OK"


if __name__ == "__main__":
    # If A = 0, then S = (Av^u)^b = 0^b = 0
    run_client(0)
    # If A = n^x, where x \in Z, then S \equiv n^b \equiv 0 \pmod{n}
    run_client(n)
    run_client(n ** 2)
