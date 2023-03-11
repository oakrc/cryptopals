#!/usr/bin/env python3
import time
import secrets
import logging
import sys
import os

from typing import Callable
from itertools import zip_longest
from multiprocessing import Process
from binascii import unhexlify

from flask import Flask, request, cli
from Crypto.Hash import SHA1

from mycrypto import xor

def TimingLeakServer(delay_ms: int = 50, port: int = 8888) -> tuple[Process, Callable[[bytes], bytes]]:
    app = Flask(__name__)
    app.logger.disabled = True
    cli.show_server_banner = lambda *x: None

    log = logging.getLogger('werkzeug')
    log.disabled = True
    hmac_key = secrets.token_bytes(64)

    def hmac(message: bytes, key: bytes, H: Callable[[bytes], bytes]):
        BLOCK_SIZE = 64

        # pad key
        if len(key) > BLOCK_SIZE:
            key = H(key)
        elif len(key) < BLOCK_SIZE:
            key += (BLOCK_SIZE - len(key)) * b'\x00'


        return H(xor(key, b'\x5c' * BLOCK_SIZE) + H(xor(key, b'\x36' * BLOCK_SIZE) + message))

    def sha1_hmac(message: bytes):
        def sha1(message: bytes):
            hash = SHA1.new()
            hash.update(message)
            return hash.digest()

        return hmac(message, hmac_key, sha1)


    def insecure_compare(lhs: bytes, rhs: bytes):
        for l, r in zip_longest(lhs, rhs):
            if not (l == r and l != None):
                return False
            time.sleep(delay_ms / 1000)
        return True

    @app.route('/test')
    def test():
        file = request.args.get('file', '').encode('ascii')
        sig = unhexlify(request.args.get('signature', '').encode('ascii'))
        if insecure_compare(sig, sha1_hmac(file)):
            return 'OK', 200
        else:
            return 'Invalid signature', 500

    def run():
        # should fix weird buffering behavior on terminal
        sys.stdout = open(os.devnull, 'w')
        app.run('0.0.0.0', port)

    return Process(target=run), sha1_hmac
