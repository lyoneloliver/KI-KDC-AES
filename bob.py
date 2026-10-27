import json

from config import LISTEN_HOST, BOB_PORT, ID_ALICE
from network import create_server, accept_client, send_msg, recv_msg
from utils import encrypt_data, decrypt_data, input_key, generate_nonce, transform_nonce, chat

def handshake_with_alice(alice,kb):
    ticket=recv_msg(alice)
    print("[3] ticket dari Alice (hex):",ticket.hex())

    try:
        data=json.loads(decrypt_data(ticket,kb).decode("utf-8"))
    except ValueError:
        raise ValueError("gagal decrypt ticket (key Bob salah?)")

    if data.get("alice_id")!=ID_ALICE:
        raise ValueError("ID di ticket bukan Alice")

    session_key=bytes.fromhex(data["session_key"])
    print("[3] session key (hex):",session_key.hex())

    nonce=generate_nonce()
    encrypted_nonce=encrypt_data(nonce.encode("ascii"),session_key)
    send_msg(alice,encrypted_nonce)
    print("[4] N2:",nonce)
    print("[4] E(Ks, N2) (hex):",encrypted_nonce.hex())

    reply=recv_msg(alice)
    print("[5] balasan Alice (hex):",reply.hex())

    answer=decrypt_data(reply,session_key).decode("ascii")
    if answer!=transform_nonce(nonce):
        raise ValueError(f"f(N2) salah: {answer}")

    print("[5] f(N2) cocok:",answer)
    return session_key


if __name__=="__main__":
    server=create_server(LISTEN_HOST,BOB_PORT)

    try:
        while True:
            kb=input_key("bob key: ")
            print("Bob menunggu di port",BOB_PORT)

            alice,addr=accept_client(server)
            print("koneksi dari",addr)

            try:
                session_key=handshake_with_alice(alice,kb)
            except (ValueError, KeyError, OSError) as error:
                print(error)
                alice.close()
                continue

            print("handshake selesai, ketik pesan untuk Alice (/baru untuk ganti key)")
            chat(alice,session_key,ID_ALICE)
    except (KeyboardInterrupt, EOFError):
        print()
