import json

from config import KDC_IP, KDC_PORT, ID_ALICE, ID_BOB
from network import connect_to, send_json, recv_msg
from utils import decrypt_data, input_key, generate_nonce

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


if __name__=="__main__":
    while True:
        ka=input_key("alice key: ")
        try:
            session_key,ticket=request_session_key(ka)
            break
        except (ValueError, KeyError, OSError) as error:
            print(error)
