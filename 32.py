#!/usr/bin/env python3
import time

from binascii import hexlify
from datetime import datetime
from statistics import mean

import requests

from mycrypto.timing import TimingLeakServer, TimingLeakAttack

if __name__ == '__main__':
    server_process, hmac = TimingLeakServer(5)
    file = 'id_rsa'
    real_sig = hmac(file.encode())
    print('[+] Actual signature:', hexlify(real_sig).decode())

    server_process.start()
    time.sleep(1)  # wait for server to start
    # attack_estimate_byte_delay('id_rsa', 20, 100, 2)
    attack = TimingLeakAttack()
    attack.rush = True
    attack.rush_lower_bound = 98
    attack.rush_upper_bound = 102
    attack.launch()
    server_process.terminate()
