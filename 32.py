#!/usr/bin/env python3
import time

from binascii import hexlify
from datetime import datetime
from statistics import mean

import requests

from timingleakserver import TimingLeakServer

class TimingLeakAttack():
    class SignatureFoundException(Exception):
        def __init__(self, sig: bytes):
            self.sig = sig

    class AbnormalConfidenceException(Exception):
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

        self.file: str = 'id_rsa'
        self.byte_delay: float = 0
        self.base_delay: float = 0
        self.sig: bytearray = bytearray(b'\x00' * 20)
        self.last_status_code = -1

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

        if self.show_progress:
            print(f'[*] initial base delay = {self.base_delay} ms')
            print(f'[*] initial byte delay = {self.byte_delay} ms')

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
            iter_delay_ms = [self.time() for _ in range(self.guess_byte_iters)]
            delays[byte] = mean(iter_delay_ms)
            confidences[byte] = (mean(iter_delay_ms) - self.base_delay) / self.byte_delay - i

        self.sig[i] = max(confidences, key=confidences.get) # type: ignore

        conf = int(confidences[self.sig[i]] * 100)
        if self.show_progress:
            print(f'[*] conf {str(conf).rjust(3)} at {str(i).rjust(2)}  : {hexlify(bytes(self.sig)).decode()[:(i+1)*2]}')
            print(f'[*]   base delay = {self.base_delay} ms')
            print(f'[*]   byte delay = {self.byte_delay} ms')

        if conf < self.confidence_lower_bound:
            if self.show_progress:
                print('[-] confidence too low')
            raise TimingLeakAttack.AbnormalConfidenceException
        elif conf > self.confidence_upper_bound:
            if self.show_progress:
                print('[-] confidence abnormally high')
            raise TimingLeakAttack.AbnormalConfidenceException

        current_base_delay = (sum([delay - i * self.byte_delay for delay in delays.values()]) - delays[self.sig[i]]) / 0xfe
        if current_base_delay < 0:
            current_base_delay = 0
        current_byte_delay = (delays[self.sig[i]] - self.base_delay) / (i + 1)
        if current_byte_delay < 0:
            current_byte_delay = 0

        # moving weighted average
        self.base_delay = 0.4 * self.base_delay + 0.6 * current_base_delay
        self.byte_delay = 0.3 * self.byte_delay + 0.7 * current_byte_delay

    def launch(self):
        self.estimate_delays()

        i = 0
        while i < len(self.sig):
            try:
                self.guess_byte(i)
                i += 1
            except TimingLeakAttack.AbnormalConfidenceException:
                if not self.enable_backtracking:
                    break
                self.sig[i] = 0
                i -= 1
                if i < 0:
                    i = 0
                print(f'[*] backtracking to i={i}')
            except TimingLeakAttack.SignatureFoundException:
                print(f'[+] SIGNATURE FOUND: {hexlify(bytes(self.sig)).decode("ascii")}')
                return

        print('Failed to determine signature')
        print(f'What we have: {hexlify(bytes(self.sig)).decode("ascii")}')



if __name__ == '__main__':
    server_process, hmac = TimingLeakServer(5)
    file = 'id_rsa'
    real_sig = hmac(file.encode())
    print('[+] Actual signature:', hexlify(real_sig).decode())

    server_process.start()
    time.sleep(1)  # wait for server to start
    # attack_estimate_byte_delay('id_rsa', 20, 100, 2)
    TimingLeakAttack().launch()
    server_process.terminate()
