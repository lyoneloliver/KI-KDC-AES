import socket

def create_server(host,port):
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind((host,port))
    server.listen()

    return server

def connect_to(host,port):
    client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect((host,port))

    return client

def accept_client(server):
    client,addr=server.accept()
    return client,addr

def recv_all(connection,size):
    data=b""
    while len(data)<size:
        packet=connection.recv(size-len(data))
        if not packet:
            raise ConnectionError("koneksi putus")
        data+=packet
    return data

def send_msg(connection,data):
    if isinstance(data,str):
        data=data.encode("utf-8")
    
    header=len(data).to_bytes(4,"big")
    connection.sendall(header+data)
    
def recv_msg(connection):
    header=recv_all(connection,4)
    size=int.from_bytes(header,"big")
    return recv_all(connection,size)
    
