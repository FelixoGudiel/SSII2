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

#Creación de la carpeta y el fichero NonceDB (si no existen), que almacena los nonces usados
def crearNonceDB():
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)
        with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
            file.write("")
            if os.name == "nt":
                #Para mayor seguridad, este fichero se hace invisible
                ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)
                
#Se busca en la base de datos si el nonce ha sido usado previamente. Dado el espacio de búsqueda, es
#improbable que se use el mismo dos veces, pero es conveniente comprobarlo.
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

#Añade el nonce usado a la base de datos para que no pueda volver a ser usado.
def escribirNonce(nonce):
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "ab") as file:
        file.write(nonce)
        file.write("\n".encode())

#Proceso principal
#Crear la base 
crearNonceDB()

#Conectar con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    #El contenido del mensaje a mandar. Se debe cambiar esta variable en función de la información que se desea
    #enviar.
    message = b"Cuenta1 Cuenta2 2000"
    
    #Búsqueda de un nonce válido. Hasta que no se crea uno que no esté en la base de datos, no deja de crear.
    while (True):
        nonce = str(
            #Los nonces posibles están entre 10^99 y 10^100-1, que son 9.e+99 posibilidades.
            random.randint(10**99, 10**100-1)
            ).encode("latin-1")
        #Comprobación
        res = comprobarNonce(nonce)
        #Si no está en la base de datos, se escoge ese nonce.
        if res is not False:
            break
    
    #Se genera el resumen del mensaje y el nonce combinados.
    h = hmac.new(secret_key, message + nonce, hashlib.sha256)
    #Se mandan 3 valores separados por "delimitadordelimitadordelimitador". 
    #Estos tres valores se combinan en una única cadena de bytes.
    mandar = message+ "delimitadordelimitadordelimitador".encode()
    + h.digest() + "delimitadordelimitadordelimitador".encode()
    + nonce
    #Se manda la cadena de bytes.
    s.sendall(mandar)
    #Se recibe la respuesta del servidor
    data = s.recv(1024)
    print(data)

if data is not None:
    escribirNonce(nonce)