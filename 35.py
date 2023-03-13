#!/usr/bin/env python3
import secrets
import sys

from typing import Any, Callable
from math import ceil
from asyncio import create_task, run, sleep

from Crypto.Hash import SHA1

from mycrypto import aes_128_cbc_decrypt, aes_128_cbc_encrypt

# {receiver: data_tuple or data, ...}
messages: dict[str, Any] = dict()

async def send(sender, receiver, *data):
    # simulate MITM
    if sender != 'M':
        receiver = 'M'

    if len(data) == 1:
        data = data[0]
    print(f'[*] {sender}->{receiver}: {data}\n')
    messages[receiver] = data

async def receive(identity) -> Any:
    while True:
        data = messages.pop(identity, None)
        if data is not None:
            return data
        await sleep(0.1)

def session_key(s_: int) -> bytes:
    s: bytes = b'\x00'
    if s_ != 0:
        s = s_.to_bytes(ceil(s_.bit_length() / 8), 'big')
    sha1 = SHA1.new()
    sha1.update(s)
    return sha1.digest()[:16]

async def relay(recipient):
    data = await receive('M')
    if type(data) != 'tuple':
        data = (data,)
    await send('M', recipient, *data)
    if len(data) == 1:
        data = data[0]
    return data


async def user_a():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    await send('A', 'B', p, g)
    assert 'ACK' == (await receive('A'))

    a = secrets.randbelow(sys.maxsize) % p
    A = pow(g, a, p)
    await send('A', 'B', A)

    B: int = await receive('A')

    s = pow(B, a, p)
    key = session_key(s)
    message = b'Hello from the other side'
    iv = secrets.token_bytes(16)
    ciphertext = aes_128_cbc_encrypt(message, key, iv)
    await send('A', 'B', ciphertext, iv)

    b_ciphertext, b_iv = await receive('A')

    _ = aes_128_cbc_decrypt(b_ciphertext, key, b_iv)
    # assert message == b_message



async def user_b():
    p, g = await receive('B')

    await send('B', 'A', 'ACK')

    A = await receive('B')

    b = secrets.randbelow(sys.maxsize) % p
    B = pow(g, b, p)
    await send('B', 'A', B)

    s = pow(A, b, p)
    key = session_key(s)
    a_ciphertext, a_iv = await receive('B')
    a_message = aes_128_cbc_decrypt(a_ciphertext, key, a_iv)

    iv = secrets.token_bytes(16)
    ciphertext = aes_128_cbc_encrypt(a_message, key, iv)
    await send('B', 'A', ciphertext, iv)


async def user_m1():
    # A->B: p, g
    p, _ = await receive('M')
    await send('M', 'B', p, 1)
    # B->A: ACK
    await relay('A')
    # A->B: A
    await relay('B')
    # B->A: B
    await relay('A')
    # A->B: ciphertext
    ciphertext, iv = await relay('B')
    # B->A: we don't care
    await relay('A')

    key = session_key(1)

    a_message = aes_128_cbc_decrypt(ciphertext, key, iv)
    print("A's message:", a_message)


async def user_m2():
    # A->B: p, g
    p, _ = await receive('M')
    await send('M', 'B', p, p)
    # B->A: ACK
    await relay('A')
    # A->B: A
    await relay('B')
    # B->A: B
    await relay('A')
    # A->B: ciphertext
    ciphertext, iv = await relay('B')
    # B->A: we don't care
    await relay('A')

    key = session_key(0)

    a_message = aes_128_cbc_decrypt(ciphertext, key, iv)
    print("A's message:", a_message)


async def user_m3():
    # A->B: p, g
    p, _ = await receive('M')
    await send('M', 'B', p, p - 1)
    # B->A: ACK
    await relay('A')
    # A->B: A
    await relay('B')
    # B->A: B
    await relay('A')
    # A->B: ciphertext
    ciphertext, iv = await relay('B')
    # B->A: we don't care
    await relay('A')

    try:
        key = session_key(p-1)
        a_message = aes_128_cbc_decrypt(ciphertext, key, iv).decode()
    except:
        key = session_key(1)
        a_message = aes_128_cbc_decrypt(ciphertext, key, iv).decode()
    print("A's message:", a_message)

async def mitm(user_m):
    a = create_task(user_a())
    m = create_task(user_m())
    b = create_task(user_b())
    await a
    await b
    await m

if __name__ == '__main__':
    print('=-=-=-=-=-=-')
    print('Trying g = 1')
    print('-=-=-=-=-=-=')
    run(mitm(user_m1))

    print('=-=-=-=-=-=-')
    print('Trying g = p')
    print('-=-=-=-=-=-=')
    run(mitm(user_m2))

    print('=-=-=-=-=-=-=-=-')
    print('Trying g = p - 1')
    print('-=-=-=-=-=-=-=-=')
    run(mitm(user_m3))
