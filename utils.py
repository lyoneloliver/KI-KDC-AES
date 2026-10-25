import secrets

from aes import encrypt as aes_encrypt, decrypt as aes_decrypt

def encrypt_data(data,key):
    padding_length=16-len(data)%16
    data+=bytes([padding_length])*padding_length

    ciphertext=b""
    for i in range(0,len(data),16):
        ciphertext+=aes_encrypt(data[i:i+16],key)

    return ciphertext

def decrypt_data(ciphertext,key):
    if not ciphertext or len(ciphertext)%16!=0:
        raise ValueError("panjang ciphertext harus kelipatan 16")

    plaintext=b""
    for i in range(0,len(ciphertext),16):
        plaintext+=aes_decrypt(ciphertext[i:i+16],key)

    padding_length=plaintext[-1]
    if not 1<=padding_length<=16 or plaintext[-padding_length:]!=bytes([padding_length])*padding_length:
        raise ValueError("padding salah (key salah?)")

    return plaintext[:-padding_length]

def input_key(prompt):
    while True:
        key=input(prompt)
        if key.isascii() and len(key)==16:
            return key.encode("ascii")
        print("key harus 16 karakter ASCII")

def generate_nonce():
    return secrets.token_hex(8)

def transform_nonce(nonce):
    return format(int(nonce,16)+1,"x")
