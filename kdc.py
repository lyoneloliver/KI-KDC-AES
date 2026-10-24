import json
import secrets

from config import LISTEN_HOST, KDC_PORT, ID_ALICE, ID_BOB
from network import create_server, accept_client, recv_msg, send_msg
from aes import encrypt as aes_encrypt, decrypt as aes_decrypt


def encrypt_data(data,key):
    padding_length=16-len(data)%16
    data+=bytes([padding_length])*padding_length
    
    ciphertext=b""
    
    for i in range(0,len(data),16):
        block=data[i:i+16]
        ciphertext+=aes_encrypt(block,key)
    
    return ciphertext

def decrypt_data(ciphertext,key):
    plaintext=b""
    
    for i in range(0,len(ciphertext),16):
        block=ciphertext[i:i+16]
        plaintext+=aes_decrypt(block,key)
        
    padding_length=plaintext[-1]
    return plaintext[:-padding_length]        

        
def sesh_key():
    return secrets.token_bytes(16)

def create_ticket(session_key):
    ticket={
        "session_key":session_key.hex(),
        "alice_id":ID_ALICE,
        "bob_id":ID_BOB
    }  

    plaintext=json.dumps(ticket).encode("utf-8")
    return encrypt_data(plaintext,session_key)
    
server=create_server(LISTEN_HOST,KDC_PORT)
print(KDC_PORT)

def create_response(session_key,ticket,nonce):
    response={
        "session_key":session_key.hex(),
        "nonce":nonce,
        "ticket":ticket.hex()
    }
    plaintext=json.dumps(response).encode("utf-8")  
    return encrypt_data(plaintext,session_key)



ka=input("alice key: ").encode("utf-8")
kb=input("bob key: ").encode("utf-8")

if len(ka)!=16 or len(kb)!=16:
    print("key must be 16 bytes")
    exit(1)
    
    

server=create_server(LISTEN_HOST,KDC_PORT)
print(KDC_PORT)


while True:
    client,addr=accept_client(server)
    print(client,addr)

    try:
        request=json.loads(recv_msg(client).decode("utf-8"))
        
        id_alice=request.get["id_alice"]
        id_bob=request.get["id_bob"]
        nonce=request.get["nonce"]
        
        if id_alice!=ID_ALICE or id_bob!=ID_BOB:
            send_msg(client,b"Invalid request")
            
        if not isinstance(nonce,str) or not nonce:
            send_msg(client,b"Invalid nonce")
        
        session_key=sesh_key()
        ticket=create_ticket(session_key)
        response=create_response(session_key,ticket,nonce)
        
        send_msg(client,response)
        
        print("sesh key generated, ticket created for bob and response sent to alice")
        
        
        
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(error)
    
    finally:
        client.close()