# device.py
# --------------------------------------------------------
# Este script simula el inicio del protocolo de autenticación mutua
# (fase de handshake) por parte del dispositivo.
#
# Funcionalidad:
# - Carga su ID y clave pública
# - Genera un nonce aleatorio
# - Prepara el mensaje de inicio de sesión (CommRequest)
# - Lo guarda como si se lo enviara al servidor
# --------------------------------------------------------

from protocol import generate_nonce
from cryptography.hazmat.primitives import serialization
import json
import os

# --------------------------------------------------------
# Paso 1: Leer el ID asignado previamente por la RA
# --------------------------------------------------------
with open("data/device_id.txt", "r") as f:
    device_id = f.read().strip()

# --------------------------------------------------------
# Paso 2: Cargar la clave pública ECC generada en el registro
# --------------------------------------------------------
with open("data/device_keys/public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# --------------------------------------------------------
# Paso 3: Generar un nonce aleatorio para el handshake
# --------------------------------------------------------
# Este nonce previene ataques de repetición y ayuda a asegurar
# que el intercambio sea único en cada sesión.
nonce_device = generate_nonce()

# --------------------------------------------------------
# Paso 4: Construir el mensaje inicial (CommRequest)
# --------------------------------------------------------
handshake_1 = {
    "device_id": device_id,
    "device_nonce": nonce_device.hex(),
    "device_public_key": public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
}

# --------------------------------------------------------
# Paso 5: Guardar el mensaje como si se enviara al servidor
# --------------------------------------------------------
# (En un sistema real, esto se enviaría por red; aquí se simula con archivo)
with open("data/handshake_device_to_server.json", "w") as f:
    json.dump(handshake_1, f, indent=4)

print("[✓] Mensaje 1 enviado al servidor")
