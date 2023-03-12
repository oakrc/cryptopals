#!/usr/bin/env python3
import secrets
import sys

from typing import Any
from math import ceil
from asyncio import Lock, create_task, run, sleep

from Crypto.Hash import SHA1

from mycrypto import aes_128_cbc_decrypt, aes_128_cbc_encrypt

# [(addressee, data_tuple), ...]
messages: dict[str, Any] = dict()
message_lock = Lock()

async def send(sender, receiver, *data):
    # simulate MITM
    if sender != 'M':
        receiver = 'M'
    await message_lock.acquire()

    if len(data) == 1:
        data = data[0]
    print(f'[*] {sender}->{receiver}: {data}')
    messages[receiver] = data
    message_lock.release()

async def receive(identity) -> Any:
    while True:
        await message_lock.acquire()
        data = messages.pop(identity, None)
        message_lock.release()
        if data is not None:
            return data
        await sleep(0.1)


async def user_a():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a = secrets.randbelow(sys.maxsize) % p
    A = pow(g, a, p)

    await send('A', 'B', p, g, A)
    B: int = await receive('A')

    s = pow(B, a, p)
    s = s.to_bytes(ceil(s.bit_length() / 8), 'big')
    sha1 = SHA1.new()
    sha1.update(s)
    key = sha1.digest()[:16]
    message = b'Hello from the other side'
    iv = secrets.token_bytes(16)
    ciphertext = aes_128_cbc_encrypt(message, key, iv)

    await send('A', 'B', ciphertext, iv)
    b_ciphertext, b_iv = await receive('A')
    b_message = aes_128_cbc_decrypt(b_ciphertext, key, b_iv)
    assert message == b_message



async def user_b():
    p, g, A = await receive('B')

    b = secrets.randbelow(sys.maxsize) % p
    B = pow(g, b, p)
    await send('B', 'A', B)

    s = pow(A, b, p)
    s = s.to_bytes(ceil(s.bit_length() / 8), 'big')
    sha1 = SHA1.new()
    sha1.update(s)
    key = sha1.digest()[:16]
    a_ciphertext, a_iv = await receive('B')
    a_message = aes_128_cbc_decrypt(a_ciphertext, key, a_iv)

    iv = secrets.token_bytes(16)
    ciphertext = aes_128_cbc_encrypt(a_message, key, iv)
    await send('B', 'A', ciphertext, iv)


async def user_m():
    # from A
    p, g, A = await receive('M')

    # to B
    await send('M', 'B', p, g, p)

    # from B
    B = await receive('M')

    # to A
    await send('M', 'A', p)

    # from A
    a_ciphertext, a_iv = await receive('M')

    # to B
    await send('M', 'B', a_ciphertext, a_iv)

    # from B
    b_ciphertext, b_iv = await receive('M')

    # to A
    await send('M', 'A', b_ciphertext, b_iv)

    sha1 = SHA1.new()
    sha1.update(b'')
    key = sha1.digest()[:16]

    print('Attempting to decrypt ciphertext from A...')
    a_message = aes_128_cbc_decrypt(a_ciphertext, key, a_iv)
    print("A's message:", a_message)

    print('Attempting to decrypt ciphertext from B...')
    b_message = aes_128_cbc_decrypt(b_ciphertext, key, b_iv)
    print("B's message:", b_message)

    assert a_message == b_message
    print(f'Successfully decrypted message: {a_message.decode()}')

async def main():
    a = create_task(user_a())
    m = create_task(user_m())
    b = create_task(user_b())
    await a
    await b
    await m

if __name__ == '__main__':
    run(main())
