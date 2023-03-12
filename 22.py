#!/usr/bin/env python3
from random import randint
import time
from mycrypto.random import MT19937

def unix_time():
    return int(time.time())


if __name__ == '__main__':
    secs = randint(40, 1000)
    print(f'Sleeping for {secs} seconds...')
    time.sleep(secs)

    seed = unix_time() - randint(40, 1000)
    randnum = MT19937(seed).get()

    secs = randint(40, 1000)
    print(f'Number generated. Sleeping for another {secs} seconds...')
    time.sleep(randint(40, 1000))

    offset = 0
    ctime = unix_time()
    print('Cracking seed...')
    while True:
        current_randnum = MT19937(ctime + offset).get()
        if current_randnum == randnum:
            assert ctime + offset == seed
            print(f'Seed found: {ctime + offset}')
            break
        offset -= 1
