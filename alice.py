import json

from config import KDC_IP, KDC_PORT, BOB_IP, BOB_PORT, ID_ALICE, ID_BOB
from network import connect_to, send_json, send_msg, recv_msg
from utils import encrypt_data, decrypt_data, input_key, generate_nonce, transform_nonce

def request_session_key(ka):
    nonce=generate_nonce()
    request={"id_alice":ID_ALICE,"id_bob":ID_BOB,"nonce":nonce}

    kdc=connect_to(KDC_IP,KDC_PORT)
    try:
        send_json(kdc,request)
        print("[1] request ke KDC:",request)

        response=recv_msg(kdc)
    finally:
        kdc.close()

    if len(response)%16!=0:
        raise ValueError(f"KDC menolak: {response.decode('utf-8','replace')}")

    print("[2] response dari KDC (hex):",response.hex())

    try:
        data=json.loads(decrypt_data(response,ka).decode("utf-8"))
    except ValueError:
        raise ValueError("gagal decrypt response KDC (key Alice salah?)")

    if data.get("nonce")!=nonce:
        raise ValueError("nonce dari KDC tidak cocok, kemungkinan replay")

    session_key=bytes.fromhex(data["session_key"])
    ticket=bytes.fromhex(data["ticket"])

    print("[2] nonce cocok:",nonce)
    print("[2] session key (hex):",session_key.hex())
    print("[2] ticket untuk Bob (hex):",ticket.hex())

    return session_key,ticket

def handshake_with_bob(session_key,ticket):
    bob=connect_to(BOB_IP,BOB_PORT)
    try:
        send_msg(bob,ticket)
        print("[3] ticket dikirim ke Bob")

        encrypted_nonce=recv_msg(bob)
        print("[4] E(Ks, N2) dari Bob (hex):",encrypted_nonce.hex())

        nonce=decrypt_data(encrypted_nonce,session_key).decode("ascii")
        print("[4] N2:",nonce)

        answer=transform_nonce(nonce)
        reply=encrypt_data(answer.encode("ascii"),session_key)
        send_msg(bob,reply)
        print("[5] f(N2):",answer)
        print("[5] E(Ks, f(N2)) (hex):",reply.hex())
    except Exception:
        bob.close()
        raise

    return bob


if __name__=="__main__":
    while True:
        ka=input_key("alice key: ")
        try:
            session_key,ticket=request_session_key(ka)
            bob=handshake_with_bob(session_key,ticket)
            break
        except (ValueError, KeyError, OSError) as error:
            print(error)

    print("handshake selesai")
    bob.close()
