from Crypto.Cipher import AES

from mycrypto import chop, pad, read_b64, unpad


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([i ^ j for i, j in zip(a, b)])


# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
# the diagram's super helpful
def aes_128_cbc_encrypt(src: bytes, k: bytes, iv: bytes) -> bytes:
    sink = b''
    src = pad(src)
    last = iv
    for block in chop(src):
        aes = AES.new(k, AES.MODE_ECB)
        last = aes.encrypt(xor(block, last))
        sink += last
    return sink


def aes_128_cbc_decrypt(src: bytes, k: bytes, iv: bytes) -> bytes:
    sink = b''
    last = iv
    for block in chop(src):
        aes = AES.new(k, AES.MODE_ECB)
        sink += xor(aes.decrypt(block), last)
        last = block
    return unpad(sink)


def aes_128_cbc_works(m: bytes, k: bytes, iv: bytes = b'\0'*16):
    c = aes_128_cbc_encrypt(m, k, iv)
    pt = aes_128_cbc_decrypt(c, k, iv)
    return m == pt


def main():
    c = read_b64('data/10.txt')
    k = b'YELLOW SUBMARINE'
    print(aes_128_cbc_decrypt(c, k, b'\0'*16).decode('ascii'))


if __name__ == "__main__":
    main()
