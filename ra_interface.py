# ra_interface.py
# --------------------------------------------------------
# Este módulo proporciona funciones que simulan la interfaz
# entre el Servidor de Aplicaciones y la Autoridad de Registro (RA).
#
# Funcionalidad:
# - Verificar si un dispositivo (por su ID) está registrado
# - Obtener la clave pública de un dispositivo registrado
#
# Estas funciones se utilizan en el servidor para validar
# dispositivos durante el proceso de autenticación.
# --------------------------------------------------------

import json
import os

# Ruta del archivo donde la RA guarda los dispositivos registrados
RA_DB_PATH = "data/registered_devices.json"

def ra_verify_device_id(device_id):
    """
    Verifica si el ID del dispositivo existe en la base de datos de la RA.

    Parámetros:
        device_id (str): El identificador único del dispositivo.

    Retorna:
        bool: True si el ID está registrado, False en caso contrario.
    """
    if not os.path.exists(RA_DB_PATH):
        print("[RA Interface] No se encontró la base de datos de la RA.")
        return False

    with open(RA_DB_PATH, "r") as f:
        db = json.load(f)

    return device_id in db

def ra_get_device_public_key(device_id):
    """
    Recupera la clave pública de un dispositivo registrado.

    Parámetros:
        device_id (str): El identificador único del dispositivo.

    Retorna:
        str or None: La clave pública en formato PEM si el dispositivo está registrado, None si no lo está.
    """
    if not os.path.exists(RA_DB_PATH):
        return None

    with open(RA_DB_PATH, "r") as f:
        db = json.load(f)

    # Retorna la clave pública asociada al ID (si existe)
    return db.get(device_id, {}).get("public_key", None)
