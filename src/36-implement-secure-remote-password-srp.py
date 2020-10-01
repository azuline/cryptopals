"""
We are doing to do this with sockets!

Too lazy to implement agreement on NIST prime, let's treat it as another constant...

Execute script with "server" argument to start server, "client" argument to start client.
"""

import socket
import sys
from hashlib import pbkdf2_hmac, sha256
from hmac import compare_digest
from secrets import randbelow
from secrets import token_bytes as random_bytes

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

password = b"letmein"


def run_server():
    sock = socket.create_server(("127.0.0.1", PORT))

    # Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

    while True:
        print("Server: Waiting for client...")

        conn, _ = sock.accept()

        print("Server: Client connection accepted.")

        # Generate salt as random integer
        # Generate string xH=SHA256(salt|password)
        # Convert xH to integer x somehow (put 0x on hexdigest)
        # Generate v=g**x % N
        # Save everything but x, xH

        print("Server: Generating salt, x, v")

        salt = random_bytes(16)
        xH = sha256(salt + password).digest()
        x = int.from_bytes(xH, "little")
        v = pow(g, x, n)
        del xH, x

        # Receive I, A=g**a % N (a la Diffie Hellman)

        print("Server: Receiving A from client")

        A = int.from_bytes(conn.recv(1600), "little")

        # Send salt, B=kv + g**b % N

        print("Server: Sending salt, B to client")

        b = randbelow(n)
        B = k * v + pow(g, b, n)

        conn.send(salt)
        conn.send(B.to_bytes(1600, "little"))

        # Compute string uH = SHA256(A|B), u = integer of uH

        print("Server: Calculating u")

        uH = sha256((A + B).to_bytes(1600, "little")).digest()
        u = int.from_bytes(uH, "little")

        # Generate S = (A * v**u) ** b % N
        # Generate K = SHA256(S)

        print("Server: Calculating S, K")

        S = pow(A * pow(v, u, n), b, n)
        K = sha256(S.to_bytes(1600, "little")).digest()

        # Send "OK" if HMAC-SHA256(K, salt) validates

        print("Server: Receiving HMAC from client")

        hmac = pbkdf2_hmac("sha256", K, salt, 100000)
        client_hmac = conn.recv(32)

        if compare_digest(hmac, client_hmac):
            print("Server: HMAC validated!")
            conn.send(b"OK")
        else:
            print("Server: HMAC NOT validated :-(")
            conn.send(b"NOT OK")

        conn.close()


def run_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", PORT))

    print("Client: Connected to server socket")

    # Send I, A=g**a % N (a la Diffie Hellman)

    print("Client: Sending A to server")

    a = randbelow(n)
    A = pow(g, a, n)

    sock.send(A.to_bytes(1600, "little"))

    # Receive salt, B=kv + g**b % N

    print("Client: Receiving salt, B from server")

    salt = sock.recv(16)
    B = int.from_bytes(sock.recv(1600), "little")

    # Compute string uH = SHA256(A|B), u = integer of uH

    print("Client: Calculating u")

    uH = sha256((A + B).to_bytes(1600, "little")).digest()
    u = int.from_bytes(uH, "little")

    # Generate string xH=SHA256(salt|password)
    # Convert xH to integer x somehow (put 0x on hexdigest)
    # Generate S = (B - k * g**x)**(a + u * x) % N
    # Generate K = SHA256(S)

    print("Client: Calculating x, S, K")

    xH = sha256(salt + password).digest()
    x = int.from_bytes(xH, "little")
    S = pow(B - k * pow(g, x, n), (a + u * x), n)
    K = sha256(S.to_bytes(1600, "little")).digest()

    # Send HMAC-SHA256(K, salt)

    print("Client: Calculating and sending HMAC to server")

    hmac = pbkdf2_hmac("sha256", K, salt, 100000)
    sock.send(hmac)

    # Receive "OK" if HMAC-SHA256(K, salt) validates

    okay = sock.recv(16)

    print(f"Client: Received {okay.decode()} from server")

    sock.close()


if __name__ == "__main__":
    try:
        arg = sys.argv[1]
    except IndexError:
        arg = None

    if arg == "server":
        run_server()
    elif arg == "client":
        run_client()
    else:
        print("Call with `server` or `client`.")
