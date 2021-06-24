import secrets
from mycrypto import aes_128_ecb_decrypt, aes_128_ecb_encrypt, chop, pad

key = secrets.token_bytes(16)


def parse_query(query: bytes) -> dict[bytes, bytes]:
    pairs = [pair.split(b'=') for pair in query.split(b'&')]
    return {p[0]: p[1] for p in pairs}


def profile_for(email: bytes) -> bytes:
    email = email.replace(b'&', b'')
    email = email.replace(b'=', b'')
    return b'email=' + email + b'&uid=10&role=user'


def get_encrypted_profile(email: bytes) -> bytes:
    return aes_128_ecb_encrypt(profile_for(email), key)


def parse_encrypted_profile(data: bytes) -> dict[bytes, bytes]:
    return parse_query(aes_128_ecb_decrypt(data, key))


def main():
    print(parse_encrypted_profile(get_encrypted_profile(b'foo@bar.com')))
    profile = b''.join(chop(get_encrypted_profile(b'aaaaaaaa@x.co'))[:-1])
    profile += chop(get_encrypted_profile(b'aaaaa@x.co' + pad(b'admin')))[1]
    print(parse_encrypted_profile(profile))


if __name__ == "__main__":
    main()
