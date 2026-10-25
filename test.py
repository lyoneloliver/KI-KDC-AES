import json
import secrets
import threading

from aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from config import LISTEN_HOST, BOB_PORT, ID_ALICE, ID_BOB
from network import create_server, accept_client
from utils import encrypt_data, decrypt_data, transform_nonce
from alice import handshake_with_bob
from bob import handshake_with_alice

def check(name,condition):
    print("OK  " if condition else "GAGAL",name)
    if not condition:
        exit(1)

def test_aes():
    key=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext=bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext=bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    check("AES encrypt sesuai FIPS-197",aes_encrypt(plaintext,key)==ciphertext)
    check("AES decrypt sesuai FIPS-197",aes_decrypt(ciphertext,key)==plaintext)

def test_utils():
    key=b"abcdefghijklmnop"
    for message in [b"",b"halo",b"x"*16,b"y"*40]:
        ciphertext=encrypt_data(message,key)
        check(f"encrypt lalu decrypt {len(message)} byte",len(ciphertext)%16==0 and decrypt_data(ciphertext,key)==message)

    try:
        decrypt_data(encrypt_data(b"halo",key),b"ponmlkjihgfedcba")
        check("key salah ditolak",False)
    except ValueError:
        check("key salah ditolak",True)

    check("f(N) = N + 1",transform_nonce("0330f6105cde61e7")=="0330f6105cde61e8")

def test_handshake():
    kb=b"bobbobbobbobBob1"
    session_key=secrets.token_bytes(16)
    ticket=encrypt_data(json.dumps({"session_key":session_key.hex(),"alice_id":ID_ALICE,"bob_id":ID_BOB}).encode("utf-8"),kb)

    server=create_server(LISTEN_HOST,BOB_PORT)
    result={}

    def run_bob():
        alice,_=accept_client(server)
        result["bob"]=handshake_with_alice(alice,kb)
        alice.close()

    bob_thread=threading.Thread(target=run_bob)
    bob_thread.start()

    bob=handshake_with_bob(session_key,ticket)
    bob_thread.join()
    bob.close()
    server.close()

    check("langkah 3-5: Bob dapat session key yang sama",result.get("bob")==session_key)


if __name__=="__main__":
    test_aes()
    test_utils()
    test_handshake()
    print("semua tes lolos")
