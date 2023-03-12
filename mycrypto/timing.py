#!/usr/bin/env python3
import time
import secrets
import logging
import sys
import os

from binascii import hexlify
from datetime import datetime
from statistics import mean
from typing import Callable
from itertools import zip_longest
from multiprocessing import Process
from binascii import unhexlify

import requests

from flask import Flask, request, cli
from Crypto.Hash import SHA1

from .mycrypto import xor

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


class TimingLeakAttack():


    class SignatureFoundException(Exception):
        def __init__(self, sig: bytes):
            self.sig = sig


    class ConfidenceTooHighException(Exception):
        pass


    class ConfidenceTooLowException(Exception):
        pass


    def __init__(self):
        self.estimate_delay_iters: int = 20
        self.improve_estimate_iters: int = 50
        self.guess_byte_iters: int = 2 # prevents backtracking but slows things
        self.enable_backtracking = True # very expensive for large i

        self.server_port: int = 8888
        self.show_progress: bool = True

        self.confidence_upper_bound: int = 130
        self.confidence_lower_bound: int = 70

        self.rush: bool = False # note that this may affect delay estimates
        self.auto_rush_threshold: int = 10 # min byte_delay to turn on rush automatically
        self.rush_lower_bound: int = 95
        self.rush_upper_bound: int = 105

        self.file: str = 'id_rsa' # doesn't matter
        self.byte_delay: float = 0 # ms
        self.base_delay: float = 0 # ms
        self.sig: bytearray = bytearray(b'\x00' * 20)


    def time(self) -> float:
        t1 = datetime.now()
        url = f'http://127.0.0.1:{self.server_port}/test?file={self.file}&signature={hexlify(self.sig).decode("ascii")}'
        code = requests.get(url).status_code
        t2 = datetime.now()
        if code == 200:
            raise TimingLeakAttack.SignatureFoundException(self.sig)
        return (t2 - t1).total_seconds() * 1000


    def estimate_delays(self):
        delays: dict[int, float] = {b : 0 for b in range(0x100)}
        for byte in range(0x100):
            self.sig[0] = byte
            iter_delay_ms = [self.time() for _ in range(self.estimate_delay_iters)]
            delays[byte] = mean(iter_delay_ms)
        self.sig[0] = max(delays, key=delays.get) # type: ignore
        self.byte_delay = delays[self.sig[0]]
        self.base_delay = (sum(delays.values()) - self.byte_delay) / 0xfe
        self.byte_delay -= self.base_delay

        if self.byte_delay > self.auto_rush_threshold:
            self.rush = True

        if self.show_progress:
            print(f'[*] initial base delay = {self.base_delay} ms')
            print(f'[*] initial byte delay = {self.byte_delay} ms')

        if self.improve_estimate_iters == 0:
            return

        iter_delay_ms = [self.time() for _ in range(self.improve_estimate_iters)]
        self.byte_delay = mean(iter_delay_ms)
        self.byte_delay -= self.base_delay
        if self.show_progress:
            print(f'[*] improved byte delay = {self.byte_delay} ms')


    def guess_byte(self, i: int):
        confidences: dict[int, float] = {b : 0 for b in range(0x100)}
        delays: dict[int, float] = {b : 0 for b in range(0x100)}
        for byte in range(0x100):
            self.sig[i] = byte
            iter_delay_ms = []
            for _ in range(self.guess_byte_iters):
                iter_delay_ms.append(self.time())
                if self.rush:
                    bconf = (mean(iter_delay_ms) - self.base_delay) / self.byte_delay - i
                    bconf = int(bconf * 100)
                    if self.rush_lower_bound <= bconf and bconf <= self.rush_upper_bound:
                        if self.show_progress:
                            print(f'[*] conf {str(bconf).rjust(3)} at {str(i).rjust(2)}  : {hexlify(bytes(self.sig)).decode()[:(i+1)*2]}')
                        return
            delays[byte] = mean(iter_delay_ms)
            confidences[byte] = (mean(iter_delay_ms) - self.base_delay) / self.byte_delay - i

        self.sig[i] = max(confidences, key=confidences.get) # type: ignore

        conf = int(confidences[self.sig[i]] * 100)
        if self.show_progress:
            print(f'[*] conf {str(conf).rjust(3)} at {str(i).rjust(2)}  : {hexlify(bytes(self.sig)).decode()[:(i+1)*2]}')
            print(f'[*]   base delay = {self.base_delay} ms')
            print(f'[*]   byte delay = {self.byte_delay} ms')

        self.check_confidence(conf)
        self.improve_estimates(i, delays)


    def check_confidence(self, conf):
        if conf < self.confidence_lower_bound:
            if self.show_progress:
                print('[-] confidence too low')
            raise TimingLeakAttack.ConfidenceTooLowException
        elif conf > self.confidence_upper_bound:
            if self.show_progress:
                print('[-] confidence abnormally high')
            raise TimingLeakAttack.ConfidenceTooHighException


    def improve_estimates(self, i: int, delays: dict[int, float]):
        current_base_delay = (sum([delay - i * self.byte_delay for delay in delays.values()]) - delays[self.sig[i]]) / 0xfe
        if current_base_delay < 0:
            current_base_delay = 0
        current_byte_delay = (delays[self.sig[i]] - self.base_delay) / (i + 1)
        if current_byte_delay < 0:
            current_byte_delay = 0


        # moving weighted average
        self.base_delay = 0.4 * self.base_delay + 0.6 * current_base_delay
        self.byte_delay = 0.3 * self.byte_delay + 0.7 * current_byte_delay


    def launch(self) -> bool:
        self.estimate_delays()

        i = 0
        while i < len(self.sig):
            try:
                self.guess_byte(i)
                i += 1
            except TimingLeakAttack.ConfidenceTooLowException:
                if not self.enable_backtracking:
                    break
                self.sig[i] = 0
                i -= 1
                if i < 0:
                    i = 0
                if self.show_progress:
                    print(f'[*] backtracking to i={i}')
            except TimingLeakAttack.ConfidenceTooHighException:
                if self.show_progress:
                    print(f'[*] retrying i={i}')
            except TimingLeakAttack.SignatureFoundException:
                if self.show_progress:
                    print(f'[+] SIGNATURE FOUND: {hexlify(bytes(self.sig)).decode("ascii")}')
                return True

        if self.show_progress:
            print('Failed to determine signature')
            print(f'What we have: {hexlify(bytes(self.sig)).decode("ascii")}')
        return False
