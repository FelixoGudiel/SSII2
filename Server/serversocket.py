# serversocket.py

import ctypes
import os
import socket
import hashlib
import hmac
from stat import FILE_ATTRIBUTE_HIDDEN

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)
secret_key = b'my_secret_key'

def crearNonceDB():
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)
        with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
            file.write("")
            if os.name == "nt":
                ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)
                
def comprobarNonce(nonce):
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "rb") as file:
        presente = False
        for line in file:
            if line[:-1]==nonce:
                presente = True
        if not presente:
            return False
        else:
            return True

def escribirNonce(nonce):
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "ab") as file:
        file.write(nonce.encode())
        file.write("\n".encode())
           
        
crearNonceDB()             
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            decoded = data.decode("latin-1")
            partes = decoded.split("delimitadordelimitadordelimitador")
            h = hmac.new(secret_key, partes[0].encode() + partes[2].encode(), hashlib.sha256)
            if (h.digest().decode('latin-1') == partes[1]):
                presente = comprobarNonce(partes[2])
                if not presente:
                    conn.sendall(b'Bien')
                    escribirNonce(partes[2])
                else:
                    conn.sendall(b'replay!')
            else:
                conn.sendall(b'Hash mal')