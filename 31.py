#!/usr/bin/env python3
import time

from binascii import hexlify
from datetime import datetime
from statistics import mean

import requests

from mycrypto.timing import TimingLeakServer, TimingLeakAttack


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

def attack_estimate_byte_delay(
        file: str = 'id_rsa',
        est_delay_iters: int = 20,
        improve_delay_iters: int = 50,
        guess_byte_iters: int = 1,
        server_port: int = 8888,
        show_progress: bool = True):

    # Pro: much faster than the other approach (only 8 minutes)
    # Con: high chance of failing for i < 8
    # Potential improvements: backtracking

    sig = bytearray(b'\x00' * 20)  # SHA-1 is 20 bytes long

    # find right first byte
    delays: dict[int, float] = {b : 0 for b in range(0x100)}
    for byte in range(0x100):
        sig[0] = byte
        iter_delay_ms = []
        for i in range(est_delay_iters):
            t1 = datetime.now()
            res = requests.get(f'http://127.0.0.1:{server_port}/test?file={file}&signature={hexlify(sig).decode("ascii")}')
            t2 = datetime.now()
            iter_delay_ms.append((t2 - t1).total_seconds() * 1000)
        delays[byte] = sum(iter_delay_ms) / est_delay_iters
    sig[0] = max(delays, key=delays.get) # type: ignore

    # estimate delay
    byte_delay = delays[sig[0]]
    # del delays[sig[0]]
    base_delay = mean(delays.values())
    # base_delay = sum(delays.values()) / (0xff - 1)
    # byte_delay -= base_delay
    # base_delay = sum(delays.values()) + base_delay
    # base_delay /= 0xff

    if show_progress:
        print(f'[*] base delay = {base_delay} ms')

    # improve byte estimate
    iter_delay_ms = []
    for i in range(improve_delay_iters):
        t1 = datetime.now()
        res = requests.get(f'http://127.0.0.1:{server_port}/test?file={file}&signature={hexlify(sig).decode("ascii")}')
        t2 = datetime.now()
        iter_delay_ms.append((t2 - t1).total_seconds() * 1000)
    byte_delay = mean(iter_delay_ms)
    byte_delay -= base_delay

    if show_progress:
        print(f'[*] byte delay = {byte_delay} ms')

    for i in range(1, len(sig)):
        confidences: dict[int, float] = {b : 0 for b in range(0x100)}
        delays: dict[int, float] = {b : 0 for b in range(0x100)}
        for byte in range(0x100):
            sig[i] = byte
            iter_delay_ms = []
            for _ in range(guess_byte_iters):
                t1 = datetime.now()
                res = requests.get(f'http://127.0.0.1:{server_port}/test?file={file}&signature={hexlify(sig).decode("ascii")}')
                t2 = datetime.now()
                iter_delay_ms.append((t2 - t1).total_seconds() * 1000)

                if res.status_code == 200:
                    print(f'[+] SIGNATURE FOUND: {hexlify(bytes(sig)).decode("ascii")}')
                    return

            delays[byte] = mean(iter_delay_ms)
            confidences[byte] = (mean(iter_delay_ms) - base_delay) / byte_delay - i

        sig[i] = max(confidences, key=confidences.get) # type: ignore
        current_byte_delay = (delays[sig[i]] - base_delay) / (i + 1)
        base_delay = 0.85 * base_delay + 0.15 * (sum([delay - i * byte_delay for delay in delays.values()]) - delays[sig[i]]) / 0xfe
        byte_delay = 0.3 * byte_delay + 0.7 * current_byte_delay


        conf = int(confidences[sig[i]] * 100)
        if show_progress:
            print(f'[*] conf {str(conf).rjust(3)} at {str(i).rjust(2)}  : {hexlify(bytes(sig)).decode()[:(i+1)*2]}')
            print(f'[*]   base delay = {base_delay} ms')
            print(f'[*]   byte delay = {byte_delay} ms')

        if conf < 50:
            print('[-] confidence too low, aborting attack')
            return
        elif conf > 150:
            print('[-] abnormal confidence, aborting attack')
            return

    print('Failed to determine signature')
    print(f'What we have: {hexlify(bytes(sig)).decode("ascii")}')


if __name__ == '__main__':
    server_process, hmac = TimingLeakServer(50)
    file = 'id_rsa'
    real_sig = hmac(file.encode())
    print('[+] Actual signature:', hexlify(real_sig).decode())

    server_process.start()
    time.sleep(1)  # wait for server to start
    # attack_max_average_delay(file, 3, 8888, True)
    attack = TimingLeakAttack()
    attack.estimate_delay_iters = 10
    attack.improve_estimate_iters = 0
    attack.guess_byte_iters = 1
    attack.rush = True
    attack.launch()
    server_process.terminate()
