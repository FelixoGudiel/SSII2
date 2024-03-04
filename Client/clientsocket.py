# clientsocket.py

import random
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
                
def comprobarNonce(nonce):
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "rb") as file:
        presente = False
        for line in file:
            if line[:-1]==nonce: 
                presente = True
        if not presente:
            return nonce
        else:
            return False

def escribirNonce(nonce):
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "ab") as file:
        file.write(nonce)
        file.write("\n".encode())

        
crearNonceDB()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    message = b"Cuenta1 Cuenta2 2000"
    
    while (True):
        nonce = str(
            random.randint(10**99, 10**100-1)
            ).encode("latin-1")
        res = comprobarNonce(nonce)
        if res is not False:
            break
    
    h = hmac.new(secret_key, message + nonce, hashlib.sha256)
    mandar = message+ "delimitadordelimitadordelimitador".encode() + h.digest() + "delimitadordelimitadordelimitador".encode() + nonce
    s.sendall(mandar)
    data = s.recv(1024)
    print(data)

if data is not None:
    escribirNonce(nonce)