import os

#IP bisa di-set lewat environment variable, contoh: KDC_IP=192.168.1.10 python alice.py
#alice.py dan bob.py juga akan menanyakan IP saat dijalankan (enter = pakai nilai di bawah)
KDC_IP = os.environ.get("KDC_IP","127.0.0.1")
ALICE_IP = os.environ.get("ALICE_IP","127.0.0.1")
BOB_IP = os.environ.get("BOB_IP","127.0.0.1")

KDC_PORT = int(os.environ.get("KDC_PORT",5000))
ALICE_PORT = int(os.environ.get("ALICE_PORT",5001))
BOB_PORT = int(os.environ.get("BOB_PORT",5002))

LISTEN_HOST = "0.0.0.0"

ID_KDC = "KDC"
ID_ALICE = "Alice"
ID_BOB = "Bob"

AES_BLOCK_SIZE = 16
