import logging
from importlib import import_module
from secrets import token_bytes
from threading import Thread
from time import sleep, time

import requests
from flask import Flask, Response, request

twentyeight = import_module('28-implement-a-sha-1-keyed-mac')

sha1 = twentyeight.sha1

# Shut Flask and Werkzeug up.
wzlogger = logging.getLogger('werkzeug')
wzlogger.disabled = True


def hmac_sha1(key: bytes, message: bytes):
    block_size = 64

    if len(key) > block_size:
        key = sha1(key)
    elif len(key) < block_size:
        key += b'\x00' * (len(key) - block_size)

    o_key_pad = bytes([k ^ 0x5C for k in key])
    i_key_pad = bytes([k ^ 0x36 for k in key])

    return sha1(o_key_pad + sha1(i_key_pad + message))


def start_webserver():
    app = Flask('vulnerable hmac server :(')

    @app.route('/test', methods=['POST'])
    def recv_file():
        file = bytes.fromhex(request.args['file'])
        user_sig = bytes.fromhex(request.args['signature'])

        correct_sig = hmac_sha1(secret_key, file)

        if insecure_compare(user_sig, correct_sig):
            return Response('1', 200)
        return Response('0', 500)

    app.run(debug=True, use_reloader=False)


def insecure_compare(sig1, sig2):
    if len(sig1) != len(sig2):
        return False

    for c1, c2 in zip(sig1, sig2):
        sleep(0.005)
        if c1 != c2:
            return False

    return True


def crack_mac_for_any_file(file):
    print('\nCracking MAC...')
    mac = b''
    for _ in range(20):
        next_mac_char = None
        longest_time_taken = 0

        for i in range(256):
            bi = bytes([i])
            padding = b'\x00' * (20 - (len(mac) + 1))

            sum_time_taken = 0
            for _ in range(5):
                start_time = time()
                r = requests.post(
                    'http://localhost:5000/test',
                    params={
                        'file': file.hex(),
                        'signature': (mac + bi + padding).hex(),
                    },
                )
                end_time = time()
                sum_time_taken += end_time - start_time

            # Take the average to balance out variances in runtime/network/etc.
            time_taken = sum_time_taken / 5
            if time_taken > longest_time_taken:
                next_mac_char = bi
                longest_time_taken = time_taken

        # If it isn't, then we probably have an incorrect character :/
        assert longest_time_taken > (len(mac) - 1) * 0.005

        print(f'Found a byte of the mac: {next_mac_char.hex()}')
        mac += next_mac_char

    assert r.status_code == 200  # Assert that the last MAC was valid.
    return mac


if __name__ == '__main__':
    print('Starting webserver.')
    Thread(target=start_webserver).start()

    sleep(1)

    file = token_bytes(24)
    print('\nThe file is:')
    print(file)

    secret_key = token_bytes(64)
    print('\nThe secret key is:')
    print(secret_key.hex())

    print('\nThe MAC is:')
    print(hmac_sha1(secret_key, file).hex())

    mac = crack_mac_for_any_file(file)
    print('\nFound full MAC:')
    print(mac.hex())
