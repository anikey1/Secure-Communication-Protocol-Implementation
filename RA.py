# ra.py
# --------------------------------------------------------
# Este script simula la Autoridad de Registro (RA),
# encargada de registrar dispositivos en el sistema.
#
# Funcionalidad:
# - Recibe la clave pública de un dispositivo
# - Genera un ID único para el dispositivo
# - Guarda la información en una base de datos local
# - Devuelve el ID al dispositivo
# --------------------------------------------------------

import json
import os
import uuid

# Ruta de la base de datos de dispositivos registrados
RA_DB_PATH = "data/registered_devices.json"

# Ruta donde el dispositivo deja su solicitud de registro
PENDING_REG_PATH = "data/ra_pending.json"

def register_device():
    """
    Procesa una solicitud de registro pendiente del dispositivo.
    Guarda su clave pública junto con un ID único en la base de datos de la RA.
    Devuelve el ID al dispositivo simulando una respuesta.
    """
    # Verificar si hay una solicitud pendiente
    if not os.path.exists(PENDING_REG_PATH):
        print("[!] Ninguna solicitud pendiente.")
        return

    # Leer la solicitud enviada por el dispositivo
    with open(PENDING_REG_PATH, "r") as f:
        request = json.load(f)

    public_key = request["public_key"]

    # Generar un ID único para el dispositivo
    device_id = str(uuid.uuid4())

    # Cargar la base de datos existente (si existe)
    if os.path.exists(RA_DB_PATH):
        with open(RA_DB_PATH, "r") as f:
            db = json.load(f)
    else:
        db = {}

    # Registrar la clave pública del dispositivo bajo el ID generado
    db[device_id] = {
        "public_key": public_key
    }

    # Guardar la base de datos actualizada
    with open(RA_DB_PATH, "w") as f:
        json.dump(db, f, indent=4)

    # Enviar respuesta al dispositivo con el ID generado
    with open("data/ra_response.json", "w") as f:
        json.dump({"device_id": device_id}, f, indent=4)

    # Eliminar la solicitud procesada para no repetirla
    os.remove(PENDING_REG_PATH)

    print("[✓] Solicitud procesada y eliminada.")
    print(f"[✓] Dispositivo registrado con ID: {device_id}")

# --------------------------------------------------------
# Punto de entrada del script
# --------------------------------------------------------
if __name__ == "__main__":
    register_device()
