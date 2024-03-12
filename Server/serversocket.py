# serversocket.py

import ctypes
import os
import random
import socket
import hashlib
import hmac
from stat import FILE_ATTRIBUTE_HIDDEN
from datetime import datetime
import re

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)
secret_key = b"my_secret_key"


# Creación de la carpeta y el fichero NonceDB (si no existen), que almacena los nonces usados
def crearNonceDB():
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)
        with open(os.path.join(path, "NonceDB.txt"), "w", encoding="utf-8") as file:
            file.write("")
            if os.name == "nt":
                ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)


# Crea la carpeta logs y las subcarpetas avisos e informes si no existen.
def crearDirectorioLogs():
    directorio = "logs"
    directorios = ["avisos", "informes"]
    path = os.path.join(os.getcwd(), directorio)
    if not os.path.exists(path):
        os.mkdir(path)

    for dir in directorios:
        path = os.path.join(os.getcwd(), "logs", dir)
        if not os.path.exists(path):
            os.mkdir(path)


# Crea un archivo de aviso donde se guardarán las conclusiones de las transferencias de un dia.
def crearAviso(partes, respuesta):
    if respuesta == "Bien":
        conclusion = "Bien - El servidor ha recibido correctamente la transferencia"
    if respuesta == "replay!":
        conclusion = (
            "replay! - El servidor ha detectado un ataque de replay con transferencia"
        )
    if respuesta == "Hash mal":
        conclusion = "Hash mal - El servidor ha detectado un error en el hash de la transferencia"

    currentDate = datetime.now()
    logName = "logs/avisos/log_" + currentDate.strftime("%d-%m-%Y")
    logText = (
        "ALERTA "
        + str(currentDate.strftime("%d-%m-%Y %H:%M:%S"))
        + ": "
        + "["
        + partes[0]
        + "] "
        + conclusion
    )
    with open(logName, "a", encoding="utf-8") as logFile:
        logFile.write(logText + "\n")


def crearInformeGlobalBase():
    logName = "logs/informe_global"
    if not os.path.exists(logName):
        logText = (
            "TRANSACCIONES TOTALES: 0"
            + "\n"
            + "INTENTOS DE ATAQUE DE REPLAY: 0"
            + "\n"
            + "INTENTOS DE ATAQUE DE MID: 0"
            + "\n\n"
            + "RATIO DE TRANSACCIONES REALIZADAS CON ÉXITO: 0"
        )
        with open(logName, "w", encoding="utf-8") as logFile:
            logFile.write(logText)


def actualizarInformeGlobal(respuesta):
    transacciones_totales_global = 0
    ataques_replay_global = 0
    ataques_mid_global = 0

    # Actualizamos el informe global
    logName = "logs/informe_global"
    with open(logName, "r") as file:
        for line in file:
            match = re.search(r": (\d+)", line)
            if match:
                number = int(match.group(1))
                if "TRANSACCIONES TOTALES" in line:
                    transacciones_totales_global += number + 1
                elif "INTENTOS DE ATAQUE DE REPLAY" in line:
                    if respuesta == "replay!":
                        ataques_replay_global += number + 1
                    else:
                        ataques_replay_global += number
                elif "INTENTOS DE ATAQUE DE MID" in line:
                    if respuesta == "Hash mal":
                        ataques_mid_global += number + 1
                    else:
                        ataques_mid_global += number

    with open(logName, "w", encoding="utf-8") as logFile:
        try:
            ratio = round(
                (
                    transacciones_totales_global
                    - (ataques_replay_global + ataques_mid_global)
                )
                / transacciones_totales_global,
                2,
            )
        except:
            ratio = 0

        logText = (
            "TRANSACCIONES TOTALES: "
            + str(transacciones_totales_global)
            + "\n"
            + "INTENTOS DE ATAQUE DE REPLAY: "
            + str(ataques_replay_global)
            + "\n"
            + "INTENTOS DE ATAQUE DE MID: "
            + str(ataques_mid_global)
            + "\n\n"
            + "RATIO DE TRANSACCIONES REALIZADAS CON ÉXITO: "
            + str(ratio)
        )
        logFile.write(logText)


def crearInforme(partes, respuesta):
    transacciones_totales = 0
    ataques_replay = 0
    ataques_mid = 0

    cuenta = partes[0].split(" ")
    logName = "logs/informes/informe_" + cuenta[0] + "-" + cuenta[1]

    # Sumamos 1 a las transacciones totales
    transacciones_totales += 1
    # Sumamos 1 al tipo de ataque correspondiente
    if respuesta == "replay!":
        ataques_replay += 1

    if respuesta == "Hash mal":
        ataques_mid += 1

    # Comprobamos si el archivo existe
    if os.path.exists(logName):
        # Abrimos el archivo en modo lectura
        with open(logName, "r") as file:
            # Iteramos por cada línea del archivo
            for line in file:
                # Buscamos el número en la línea
                match = re.search(r": (\d+)", line)
                if match:
                    number = int(match.group(1))
                    # Sumamos el número a la variable correspondiente
                    if "TRANSACCIONES TOTALES" in line:
                        transacciones_totales += number
                    elif "INTENTOS DE ATAQUE DE REPLAY" in line:
                        ataques_replay += number
                    elif "INTENTOS DE ATAQUE DE MID" in line:
                        ataques_mid += number

        # Reescribimos el informe con los nuevos valores
        with open(logName, "w", encoding="utf-8") as logFile:
            try:
                ratio = round(
                    (transacciones_totales - (ataques_replay + ataques_mid))
                    / transacciones_totales,
                    2,
                )
            except:
                ratio = 0
            logText = (
                "TRANSACCIONES TOTALES: "
                + str(transacciones_totales)
                + "\n"
                + "INTENTOS DE ATAQUE DE REPLAY: "
                + str(ataques_replay)
                + "\n"
                + "INTENTOS DE ATAQUE DE MID: "
                + str(ataques_mid)
                + "\n\n"
                + "RATIO DE TRANSACCIONES REALIZADAS CON ÉXITO: "
                + str(ratio)
            )
            logFile.write(logText)
    # Si el archivo no existe, lo creamos
    else:
        try:
            ratio = round(
                (transacciones_totales - (ataques_replay + ataques_mid))
                / transacciones_totales,
                2,
            )
        except:
            ratio = 0

        logText = (
            "TRANSACCIONES TOTALES: "
            + str(transacciones_totales)
            + "\n"
            + "INTENTOS DE ATAQUE DE REPLAY: "
            + str(ataques_replay)
            + "\n"
            + "INTENTOS DE ATAQUE DE MID: "
            + str(ataques_mid)
            + "\n\n"
            + "RATIO DE TRANSACCIONES REALIZADAS CON ÉXITO: "
            + str(ratio)
        )
        with open(logName, "a", encoding="utf-8") as logFile:
            logFile.write(logText)

    actualizarInformeGlobal(respuesta)


# Se busca en la base de datos si el nonce ha sido usado previamente.
def comprobarNonce(nonce):
    directorio = "NonceDBServer"
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
    directorio = "NonceDBServer"
    path = os.path.join(os.getcwd(), directorio)
    with open(os.path.join(path, "NonceDB.txt"), "ab") as file:
        file.write(nonce.encode())
        file.write("\n".encode())


# Proceso principal
# Crear la base
crearNonceDB()

# Crear la carpeta logs
crearDirectorioLogs()

# Crear el informe global
crearInformeGlobalBase()

# Conectar con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    # Acepta la conexión y espera a recibir datos.
    s.listen()
    conn, addr = s.accept()
    with conn:
        # Address que se ha conectado.
        print(f"Connected by {addr}")
        while True:
            # Sección de recibir y comprobar la solicitud del cliente
            data = conn.recv(1024)
            if not data:
                break
            # Decodifica el mensaje recibido.
            decoded = data.decode("latin-1")
            # Separa los tres valores a recibir.
            partes = decoded.split("delimitadordelimitadordelimitador")
            # Crea la función resumen a partir del mensaje y el nonce recibido.
            h = hmac.new(
                secret_key, partes[0].encode() + partes[2].encode(), hashlib.sha256
            )
            respuesta = b""
            # Comprueba si el resumen enviado coincide con el recreado.
            if h.digest().decode("latin-1") == partes[1]:
                # En caso positivo, se comprueba si el nonce ya ha sido usado.
                valido = comprobarNonce(partes[2].encode())
                if valido:
                    # En caso positivo, todo bien.
                    respuesta = b"Bien"
                    escribirNonce(partes[2])
                else:
                    # En caso negativo, es un replay.
                    respuesta = b"replay!"
            else:
                # En caso negativo, alguien ha alterado el contenido/hash.
                respuesta = b"Hash mal"
            crearAviso(partes, respuesta.decode())
            crearInforme(partes, respuesta.decode())
            ###################################################################################################
            # Sección de mandar la respuesta
            while True:
                nonce = str(
                    # Los nonces posibles están entre 10^99 y 10^100-1, que son 9.e+99 posibilidades.
                    random.randint(10**99, 10**100 - 1)
                ).encode("latin-1")
                # Comprobación
                res = comprobarNonce(nonce)
                # Si no está en la base de datos, se escoge ese nonce.
                if res is not False:
                    break
            escribirNonce(nonce.decode())

            # Se genera el resumen del mensaje y el nonce combinados.
            h = hmac.new(secret_key, respuesta + nonce, hashlib.sha256)
            # Se mandan 3 valores separados por "delimitadordelimitadordelimitador".
            # Estos tres valores se combinan en una única cadena de bytes.
            mandar = (
                respuesta
                + "delimitadordelimitadordelimitador".encode()
                + h.digest()
                + "delimitadordelimitadordelimitador".encode()
                + nonce
            )
            # Se manda la cadena de bytes.
            conn.sendall(mandar)
