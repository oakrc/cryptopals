#!/usr/bin/env python3
import secrets
import sys

from typing import Any, Callable
from math import ceil
from asyncio import create_task, run, sleep

from Crypto.Hash import SHA256

from mycrypto import xor


N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = b'john.doe@example.com'
P = b'V3rY$eCUR3P4$$w0rD!'

# {receiver: data_tuple or data, ...}
messages: dict[str, Any] = dict()


async def send(sender, recipient, *data):
    if len(data) == 1:
        data = data[0]
    print(f'[*] {sender}->{recipient}: {data}\n')
    messages[recipient] = data


async def receive(identity) -> Any:
    while True:
        data = messages.pop(identity, None)
        if data is not None:
            return data
        await sleep(0.1)


def to_bytes(s_: int) -> bytes:
    s: bytes = b'\x00'
    if s_ != 0:
        s = s_.to_bytes(ceil(s_.bit_length() / 8), 'big')
    return s


def sha256(*data):
    sha256 = SHA256.new()
    for d in data:
        if isinstance(d, int):
            d = to_bytes(d)
        assert isinstance(d, bytes)
        sha256.update(d)
    return sha256.digest()


def hmac(message: bytes, key: bytes, H: Callable[..., bytes]):
    BLOCK_SIZE = 64

    # pad key
    if len(key) > BLOCK_SIZE:
        key = H(key)
    elif len(key) < BLOCK_SIZE:
        key += (BLOCK_SIZE - len(key)) * b'\x00'

    return H(xor(key, b'\x5c' * BLOCK_SIZE) + H(xor(key, b'\x36' * BLOCK_SIZE) + message))


def sha256_hmac(message: bytes, key: bytes):
    return hmac(message, key, sha256)


async def server():
    b = secrets.randbelow(sys.maxsize) % N

    salt = secrets.token_bytes(8)
    xH = sha256(salt, P)
    x = int.from_bytes(xH, 'big')
    v: int = pow(g, x, N)
    del x
    del xH

    Ic, A = await receive('S')
    if Ic != I:
        await send('S', 'C', 'UNAUTHORIZED')
        return

    assert isinstance(A, int)
    B = k*v + pow(g, b, N)
    await send('S', 'C', salt, B)

    uH = sha256(A, B)
    u = int.from_bytes(uH, 'big')

    S = pow(A * pow(v, u, N), b, N)

    K = sha256(S)


    token = sha256_hmac(K, salt)
    token_c = await receive('S')

    if token == token_c:
        await send('S', 'C', 'OK')
    else:
        await send('S', 'C', 'UNAUTHORIZED')


async def client():
    a = secrets.randbelow(sys.maxsize) % N
    A = pow(g, a, N)
    await send('C', 'S', I, A)
    salt, B = await receive('C')

    uH = sha256(A, B)
    u = int.from_bytes(uH, 'big')

    xH = sha256(salt, P)
    x = int.from_bytes(xH, 'big')

    S = pow(B - k * pow(g, x, N), a + u * x, N)
    K = sha256(S)
    await send('C', 'S', sha256_hmac(K, salt))

    result = await receive('C')
    assert result == 'OK'
    print(f'[+] Regular login works\n')


async def zero_key_attacker():
    # a = secrets.randbelow(sys.maxsize) % N
    # A = pow(g, a, N)
    A = 0
    await send('C', 'S', I, A)
    salt, _ = await receive('C')

    S = 0
    K = sha256(S)
    await send('C', 'S', sha256_hmac(K, salt))

    result = await receive('C')
    assert result == 'OK'
    print(f'[+] Zero key attack works\n')


async def main(client):
    s = create_task(server())
    c = create_task(client())
    await s
    await c


if __name__ == '__main__':
    run(main(client))
    run(main(zero_key_attacker))
