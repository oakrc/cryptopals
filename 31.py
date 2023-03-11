#!/usr/bin/env python3
import time

from binascii import hexlify
from datetime import datetime

import requests

from timingleakserver import TimingLeakServer


def attack_max_average_delay(file: str = 'id_rsa', iters: int = 10, server_port: int = 8888, debug: bool = True):
    # Pro: simple to implement
    # Con: VERY slow. hard to tell if it won't work in the beginning. sometimes
    #      an error creeps in the middle and all the bytes that follow will be wrong
    # Potential Improvements: for each byte, gather more delay measurements
    #                         until target std dev reached
    sig = bytearray(b'\x00' * 20)  # SHA-1 is 20 bytes long

    for i in range(len(sig)):
        byte_delay: dict[int, float] = {b : 0 for b in range(0x100)}
        for byte in range(0x100):
            sig[i] = byte
            iter_delay_ms = []
            for _ in range(iters):
                t1 = datetime.now()
                res = requests.get(f'http://127.0.0.1:{server_port}/test?file={file}&signature={hexlify(sig).decode("ascii")}')
                t2 = datetime.now()
                iter_delay_ms.append((t2 - t1).total_seconds() * 1000)

                if res.status_code == 200:
                    print(f'[+] SIGNATURE FOUND: {hexlify(bytes(sig)).decode("ascii")}')
                    return

            byte_delay[byte] = sum(iter_delay_ms) / iters

        sig[i] = max(byte_delay, key=byte_delay.get) # type: ignore
        if debug:
            print(f'[*] at {str(i).rjust(2)}           : {hexlify(bytes(sig)).decode()[:(i+1)*2]}')

    print('[!] Failed to determine signature')
    print(f'[!] What we have: {hexlify(bytes(sig)).decode("ascii")}')


if __name__ == '__main__':
    server_process, hmac = TimingLeakServer(50)
    file = 'id_rsa'
    real_sig = hmac(file.encode())
    print('[+] Actual signature:', hexlify(real_sig).decode())

    server_process.start()
    time.sleep(1)  # wait for server to start
    attack_max_average_delay(file, 3, 8888, True)
    server_process.terminate()
