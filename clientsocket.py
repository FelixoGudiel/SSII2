# clientsocket.py

import socket
import hashlib
import hmac
import os
import ctypes
from stat import FILE_ATTRIBUTE_HIDDEN

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 3030  # The port used by the server
secret_key = b'my_secret_key'


def crearNonceDB():
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)
        with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
            file.write("")
            if os.name == "nt":
                ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)

crearNonceDB()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    message = b"Cuenta1 Cuenta2 2000"
    
    nonce = os.urandom(32)
    
    
    h = hmac.new(secret_key, message + nonce, hashlib.sha256)
    
    s.sendall(message+ ";" + h.digest() + ";" + nonce)
    data = s.recv(1024)

print(f"Received {data!r}")

directorio = "NonceDBClient"
path = os.path.join(os.getcwd(), directorio)
with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
    file.write(nonce + "\n")