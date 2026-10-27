import secrets
import socket
import threading

from aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from network import send_msg, recv_msg

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
    return format(int(nonce,16)+1,f"0{len(nonce)}x")

def chat(conn,session_key,peer):
    done=threading.Event()

    def receive():
        while True:
            try:
                ciphertext=recv_msg(conn)
            except OSError:
                if not done.is_set():
                    print(f"\n{peer} menutup koneksi, tekan Enter")
                    done.set()
                return

            print(f"\n[{peer}] ciphertext (hex): {ciphertext.hex()}")
            try:
                print(f"[{peer}] plaintext: {decrypt_data(ciphertext,session_key).decode('ascii')}")
            except ValueError as error:
                print(f"[{peer}] gagal decrypt: {error}")

    threading.Thread(target=receive,daemon=True).start()

    while not done.is_set():
        text=input()
        if done.is_set() or text=="/baru":
            break
        if not text:
            continue
        if not text.isascii():
            print("plaintext harus ASCII")
            continue

        ciphertext=encrypt_data(text.encode("ascii"),session_key)
        send_msg(conn,ciphertext)
        print("terkirim, ciphertext (hex):",ciphertext.hex())

    done.set()
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    conn.close()
