import logging
from importlib import import_module
from secrets import token_bytes
from threading import Thread
from time import sleep, time

import requests

thirtyone = import_module(
    "31-implement-and-break-hmac-sha1-with-an-artificial-timing-leak"
)

# Shut Flask and Werkzeug up.
wzlogger = logging.getLogger("werkzeug")
wzlogger.disabled = True


def insecure_compare(sig1, sig2):
    if len(sig1) != len(sig2):
        return False

    for c1, c2 in zip(sig1, sig2):
        sleep(0.005)
        if c1 != c2:
            return False

    return True


def crack_mac_for_any_file(file):
    print("\nCracking MAC...")
    mac = b""

    for _ in range(20):
        times = []

        for byte in [bytes([i]) for i in range(256)]:
            padding = b"\x00" * (20 - (len(mac) + 1))
            total_time = 0

            for _ in range(10):
                start_time = time()
                r = requests.post(
                    "http://localhost:5000/test",
                    params={
                        "file": file.hex(),
                        "signature": (mac + byte + padding).hex(),
                    },
                )
                end_time = time()

                total_time += end_time - start_time

            times.append((byte, total_time))

        byte, longest_time = sorted(times, key=lambda v: v[1], reverse=True)[0]
        assert longest_time > (len(mac) + 1.5) * 0.05

        print(f"Found a byte of the mac: {byte.hex()}")
        mac += byte

    assert r.status_code == 200  # Assert that the last MAC was valid.
    return mac


if __name__ == "__main__":
    secret_key = token_bytes(64)

    print("Starting webserver.")
    Thread(target=thirtyone.start_webserver(insecure_compare, secret_key)).start()

    sleep(1)  # Give the webserver time to spin up...

    file = token_bytes(24)
    print("\nThe file is:")
    print(file)

    print("\nThe secret key is:")
    print(secret_key.hex())

    print("\nThe MAC is:")
    print(thirtyone.hmac_sha1(secret_key, file).hex())

    mac = crack_mac_for_any_file(file)
    print("\nFound full MAC:")
    print(mac.hex())
