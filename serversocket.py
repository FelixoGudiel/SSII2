# serversocket.py

import socket
import hashlib
import hmac

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)
secret_key = b'my_secret_key'

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
            decoded = data.decode('latin-1')
            partes = decoded.split(";")
            h = hmac.new(secret_key, partes[0].encode(), hashlib.sha256)
            if (h.digest().decode('latin-1') == partes[1]):
                conn.sendall(b'Bien')
            else:
                conn.sendall(b'Mal')