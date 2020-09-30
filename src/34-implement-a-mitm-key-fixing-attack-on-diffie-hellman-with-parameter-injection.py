"""
Assume Eve MITMs Alice and Bob somehow, this script assumes it has already
happened somehow and implements the rest.
"""

import asyncio
import json
from secrets import randbelow
from threading import Thread
from time import sleep

# fmt: off
NIST_P = int(
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
    'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
    '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
    '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
    '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
    'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
    'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
    'fffffffffffff', 16
)

NIST_G = 2

PORT_ALICE = 23727
PORT_BOB = 23728
PORT_EVE = 23729
# fmt: on


def start_alice():
    asyncio.run(server_alice())


async def server_alice():
    """Alice "decides" (let's use NIST values) p and g."""
    secret = randbelow(NIST_P)


def start_bob():
    asyncio.run(server_bob())


async def server_bob():
    """Bob responds to Alice."""
    secret = randbelow(NIST_P)


def start_eve():
    pass


async def server_eve():
    """Eve MITMs Alice and Bob."""


if __name__ == "__main__":
    print("Starting actors...", end="\n\n")
    Thread(target=start_alice).start()
    Thread(target=start_bob).start()
    Thread(target=start_eve).start()
