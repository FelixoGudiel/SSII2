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

#Creación de la carpeta y el fichero NonceDB (si no existen), que almacena los nonces usados
def crearNonceDB():
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)
        with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
            file.write("")
            if os.name == "nt":
                ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)

#Se busca en la base de datos si el nonce ha sido usado previamente. Dado el espacio de búsqueda, es
#improbable que se use el mismo dos veces, pero es conveniente comprobarlo.            
def comprobarNonce(nonce):
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "rb") as file:
        presente = False
        for line in file:
            if line[:-1]==nonce.encode():
                presente = True
        if not presente:
            return False
        else:
            return True
        
#Añade el nonce usado a la base de datos para que no pueda volver a ser usado.
def escribirNonce(nonce):
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "ab") as file:
        file.write(nonce.encode())
        file.write("\n".encode())
           
#Proceso principal
#Crear la base 
crearNonceDB()

#Conectar con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    #Acepta la conexión y espera a recibir datos.
    s.listen()
    conn, addr = s.accept()
    with conn:
        #Address que se ha conectado.
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            #Decodifica el mensaje recibido.
            decoded = data.decode("latin-1")
            #Separa los tres valores a recibir.
            partes = decoded.split("delimitadordelimitadordelimitador")
            #Crea la función resumen a partir del mensaje y el nonce recibido.
            h = hmac.new(secret_key, partes[0].encode() + partes[2].encode(), hashlib.sha256)
            respuesta = ""
            #Comprueba si el resumen enviado coincide con el recreado.
            if (h.digest().decode('latin-1') == partes[1]):
                #En caso positivo, se comprueba si el nonce ya ha sido usado.
                presente = comprobarNonce(partes[2])
                if not presente:
                    #En caso negativo, todo bien.
                    s.sendall(b'Bien')
                    escribirNonce(partes[2])
                else:
                    #En caso positivo, es un replay.
                    s.sendall(b'replay!')
            else:
                #En caso negativo, alguien ha alterado el contenido/hash.
                s.sendall(b'Hash mal')
            