import json
import secrets
import threading

from config import LISTEN_HOST, KDC_PORT, ID_ALICE, ID_BOB
from network import create_server, accept_client, recv_msg, send_msg
from utils import encrypt_data, input_key


def sesh_key():
    return secrets.token_bytes(16)

def create_ticket(session_key,kb):
    ticket={
        "session_key":session_key.hex(),
        "alice_id":ID_ALICE,
        "bob_id":ID_BOB
    }

    plaintext=json.dumps(ticket).encode("utf-8")
    return encrypt_data(plaintext,kb)

def create_response(session_key,ticket,nonce,ka):
    response={
        "session_key":session_key.hex(),
        "nonce":nonce,
        "ticket":ticket.hex()
    }
    plaintext=json.dumps(response).encode("utf-8")
    return encrypt_data(plaintext,ka)

def handle_client(client,keys):
    request=json.loads(recv_msg(client).decode("utf-8"))
    print("[1] request dari Alice:",request)

    id_alice=request.get("id_alice")
    id_bob=request.get("id_bob")
    nonce=request.get("nonce")

    if id_alice!=ID_ALICE or id_bob!=ID_BOB:
        send_msg(client,b"Invalid request")
        return

    if not isinstance(nonce,str) or not nonce:
        send_msg(client,b"Invalid nonce")
        return

    session_key=sesh_key()
    ticket=create_ticket(session_key,keys["kb"])
    response=create_response(session_key,ticket,nonce,keys["ka"])

    send_msg(client,response)

    print("[2] session key (hex):",session_key.hex())
    print("[2] ticket E(Kb) (hex):",ticket.hex())
    print("[2] response E(Ka) (hex):",response.hex())

def serve(server,keys):
    while True:
        client,addr=accept_client(server)
        print("koneksi dari",addr)

        try:
            handle_client(client,keys)
        except (ValueError, UnicodeDecodeError, OSError) as error:
            print(error)
        finally:
            client.close()


if __name__=="__main__":
    keys={}
    keys["ka"]=input_key("alice key: ")
    keys["kb"]=input_key("bob key: ")

    server=create_server(LISTEN_HOST,KDC_PORT)
    print("KDC menunggu di port",KDC_PORT)
    print("ketik /ganti untuk ganti key")

    threading.Thread(target=serve,args=(server,keys),daemon=True).start()

    try:
        while True:
            if input()=="/ganti":
                keys["ka"]=input_key("alice key baru: ")
                keys["kb"]=input_key("bob key baru: ")
                print("key diganti")
    except (KeyboardInterrupt, EOFError):
        print()
