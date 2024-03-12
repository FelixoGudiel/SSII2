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
secret_key = b"my_secret_key"


# Creación de la carpeta y el fichero NonceDB (si no existen), que almacena los nonces usados
def crearNonceDB():
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)
        with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
            file.write("")
            if os.name == "nt":
                # Para mayor seguridad, este fichero se hace invisible
                ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)


# Se busca en la base de datos si el nonce ha sido usado previamente. Dado el espacio de búsqueda, es
# improbable que se use el mismo dos veces, pero es conveniente comprobarlo.
def comprobarNonce(nonce):
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "rb") as file:
        presente = False
        for line in file:
            if line[:-1] == nonce:
                presente = True
                break
        if not presente:
            return True
        else:
            return False


# Añade el nonce usado a la base de datos para que no pueda volver a ser usado.
def escribirNonce(nonce):
    directorio = "NonceDBClient"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "ab") as file:
        file.write(nonce)
        file.write("\n".encode())


# Proceso principal
# Crear la base
crearNonceDB()

# Conectar con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # El contenido del mensaje a mandar. Se debe cambiar esta variable en función de la información que se desea
    # enviar.
    message = b"Cuenta1 Cuenta2 2000"

    # Búsqueda de un nonce válido. Hasta que no se crea uno que no esté en la base de datos, no deja de crear.
    while True:
        nonce = str(
            # Los nonces posibles están entre 10^99 y 10^100-1, que son 9.e+99 posibilidades.
            random.randint(10**99, 10**100 - 1)
        ).encode("latin-1")
        # Comprobación
        valido = comprobarNonce(nonce)
        # Si no está en la base de datos, se escoge ese nonce.
        if valido is not False:
            break
    escribirNonce(nonce)
    # Se genera el resumen del mensaje y el nonce combinados.
    h = hmac.new(secret_key, message + nonce, hashlib.sha256)
    # Se mandan 3 valores separados por "delimitadordelimitadordelimitador".
    # Estos tres valores se combinan en una única cadena de bytes.
    mandar = (
        message
        + "delimitadordelimitadordelimitador".encode()
        + h.digest()
        + "delimitadordelimitadordelimitador".encode()
        + nonce
    )
    # Se manda la cadena de bytes.
    s.sendall(mandar)

    ###################################################################################################
    # Sección de recibir y comprobar la respuesta del servidor
    # Se recibe la respuesta del servidor
    data = s.recv(1024)
    # Decodifica el mensaje recibido.
    decoded = data.decode("latin-1")
    # Separa los tres valores a recibir.
    partes = decoded.split("delimitadordelimitadordelimitador")
    # Crea la función resumen a partir del mensaje y el nonce recibido.
    h = hmac.new(secret_key, partes[0].encode() + partes[2].encode(), hashlib.sha256)
    respuesta = b""
    # Comprueba si el resumen enviado coincide con el recreado.
    if h.digest().decode("latin-1") == partes[1]:
        # En caso positivo, se comprueba si el nonce ya ha sido usado.
        valido = comprobarNonce(partes[2].encode())
        if valido:
            # En caso positivo, todo bien.
            respuesta = b"Bien"
            escribirNonce(partes[2].encode())
        else:
            # En caso negativo, es un replay.
            respuesta = b"replay!"
    else:
        # En caso negativo, alguien ha alterado el contenido/hash.
        respuesta = b"Hash mal"
    parteServidor = ""
    parteCliente = ""
    if partes[0] == "Bien":
        parteServidor = (
            'El servidor ha recibido correctamente la transferencia "'
            + message.decode()
            + '"'
        )
    if partes[0] == "replay!":
        parteServidor = (
            'El servidor ha detectado un ataque de replay con transferencia "'
            + message.decode()
            + '"'
        )
    if partes[0] == "Hash mal":
        parteServidor = (
            'El servidor ha detectado un error en el hash de la transferencia "'
            + message.decode()
            + '"'
        )

    if respuesta == b"Bien":
        parteCliente = " y se ha comprobado que el mensaje pertenece al servidor."
    if respuesta == b"replay!":
        parteCliente = " y se sabe que el mensaje ha sido reenviado por un imitador del servidor. (Replay)"
    if respuesta == b"Hash mal":
        parteCliente = " y se sabe que un imitador del servidor ha manipulado el contenido del mensaje. (Hash mal)"
    print(parteServidor + parteCliente)
