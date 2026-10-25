import secrets

from config import AES_BLOCK_SIZE
from aes import encrypt as aes_encrypt, decrypt as aes_decrypt


#PKCS#7: tambah n byte bernilai n, n = 1..16
def pad(data):
    padding_length=AES_BLOCK_SIZE-len(data)%AES_BLOCK_SIZE
    return data+bytes([padding_length])*padding_length

def unpad(data):
    if not data or len(data)%AES_BLOCK_SIZE!=0:
        raise ValueError("invalid padded data length")

    padding_length=data[-1]
    if padding_length<1 or padding_length>AES_BLOCK_SIZE:
        raise ValueError("invalid padding (wrong key?)")
    if data[-padding_length:]!=bytes([padding_length])*padding_length:
        raise ValueError("invalid padding (wrong key?)")

    return data[:-padding_length]


#mode ECB, sama dengan yang dipakai kdc.py
def encrypt_data(data,key):
    data=pad(data)

    ciphertext=b""
    for i in range(0,len(data),AES_BLOCK_SIZE):
        ciphertext+=aes_encrypt(data[i:i+AES_BLOCK_SIZE],key)

    return ciphertext

def decrypt_data(ciphertext,key):
    if len(ciphertext)%AES_BLOCK_SIZE!=0:
        raise ValueError("ciphertext length must be a multiple of 16")

    plaintext=b""
    for i in range(0,len(ciphertext),AES_BLOCK_SIZE):
        plaintext+=aes_decrypt(ciphertext[i:i+AES_BLOCK_SIZE],key)

    return unpad(plaintext)


#key harus 16 karakter ASCII (AES-128)
def parse_key(text):
    if not text.isascii():
        raise ValueError("key must be ASCII")

    key=text.encode("ascii")
    if len(key)!=AES_BLOCK_SIZE:
        raise ValueError(f"key must be {AES_BLOCK_SIZE} characters, got {len(key)}")

    return key

def input_key(prompt):
    while True:
        try:
            return parse_key(input(prompt))
        except ValueError as error:
            print(error)


def generate_nonce():
    return secrets.token_hex(8)

#f(N) pada langkah ke-5: N + 1
def transform_nonce(nonce):
    width=len(nonce)
    value=(int(nonce,16)+1)%(16**width)
    return format(value,f"0{width}x")
