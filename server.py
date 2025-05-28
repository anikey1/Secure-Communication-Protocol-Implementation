# server.py
# --------------------------------------------------------
# Este script representa al Servidor Confiable (Trusted App Server)
# en el protocolo de comunicación segura.
#
# Funcionalidad:
# - Recibe una solicitud de conexión del dispositivo (CommRequest)
# - Verifica el ID con la Autoridad de Registro (RA)
# - Recupera y valida la clave pública del dispositivo
# - Genera su propio nonce
# - Firma la información crítica del handshake
# - Responde al dispositivo con clave pública, nonce y firma
# --------------------------------------------------------

import json
import os
from protocol import *  # Funciones criptográficas comunes
from ra_interface import ra_verify_device_id, ra_get_device_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# --------------------------------------------------------
# Inicialización del servidor: claves y configuración
# --------------------------------------------------------

SERVER_ID = "server"
SERVER_KEY_PATH = f"data/device_keys/{SERVER_ID}_private.pem"

# Cargar clave privada o generar una nueva si no existe
if not os.path.exists(SERVER_KEY_PATH):
    private_key = ec.generate_private_key(ec.SECP256R1())
    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
else:
    with open(SERVER_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

# Obtener clave pública correspondiente
public_key = private_key.public_key()

# --------------------------------------------------------
# Paso 1: Recibir mensaje de handshake del dispositivo
# --------------------------------------------------------

with open("data/handshake_device_to_server.json", "r") as f:
    msg1 = json.load(f)

device_id = msg1["device_id"]
device_nonce = bytes.fromhex(msg1["device_nonce"])

print(f"[SERVER] Recibida conexión de dispositivo ID: {device_id}")

# --------------------------------------------------------
# Paso 2: Verificar si el ID del dispositivo está registrado
# --------------------------------------------------------

if not ra_verify_device_id(device_id):
    print("[SERVER] ❌ Dispositivo NO registrado. Terminando conexión.")
    exit()

# --------------------------------------------------------
# Paso 3: Obtener la clave pública verdadera desde la RA
# --------------------------------------------------------

device_pub_key_str = ra_get_device_public_key(device_id)
if not device_pub_key_str:
    print("[SERVER] ❌ No se pudo obtener la clave pública del dispositivo.")
    exit()

device_public_key = serialization.load_pem_public_key(device_pub_key_str.encode())

print("[SERVER] ✅ ID y clave pública verificadas con la RA.")

# --------------------------------------------------------
# Paso 4: Generar nonce del servidor para el handshake
# --------------------------------------------------------

nonce_server = generate_nonce()

# --------------------------------------------------------
# Paso 5: Firmar datos críticos (para autenticación mutua)
# --------------------------------------------------------

# Firma: [nonce_dispositivo || nonce_servidor || clave_pub_dispositivo || clave_pub_servidor]
message_to_sign = (
    device_nonce + nonce_server +
    device_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ) +
    public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

signature = sign_data(private_key, message_to_sign)

# --------------------------------------------------------
# Paso 6: Preparar mensaje de respuesta al dispositivo (Mensaje 2)
# --------------------------------------------------------

handshake_2 = {
    "server_nonce": nonce_server.hex(),
    "server_public_key": public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode(),
    "signature": signature.hex()
}

# Guardar mensaje como si se enviara al dispositivo
with open("data/handshake_server_to_device.json", "w") as f:
    json.dump(handshake_2, f, indent=4)

print("[SERVER] 📤 Enviado Mensaje 2: nonce, clave pública y firma")