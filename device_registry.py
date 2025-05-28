# device_register.py
# --------------------------------------------------------
# Este script simula la FASE DE REGISTRO de un dispositivo
# con una Autoridad de Registro (RA).
#
# Funcionalidad:
# - Genera un par de claves ECC (clave privada y pública)
# - Envía la clave pública a la RA para registrarse
# - Recibe un ID asignado por la RA y lo guarda localmente
# --------------------------------------------------------

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import json
import os

def generate_ecc_keys():
    """
    Genera un par de claves ECC (usando la curva SECP256R1).
    Guarda la clave privada y la pública en archivos locales.
    Devuelve la clave pública en formato PEM (texto).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Crear directorio para guardar las llaves si no existe
    os.makedirs("data/device_keys", exist_ok=True)

    # Guardar la clave privada en formato PEM
    with open("data/device_keys/private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Codificar la clave pública en formato PEM
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar la clave pública en archivo
    with open("data/device_keys/public.pem", "wb") as f:
        f.write(public_key_pem)

    return public_key_pem.decode("utf-8")

def send_registration_request(public_key_str):
    """
    Simula el envío de la solicitud de registro a la RA.
    Guarda la clave pública en un archivo JSON que la RA leerá.
    """
    with open("data/ra_pending.json", "w") as f:
        json.dump({"public_key": public_key_str}, f, indent=4)

    print("[✓] Solicitud de registro enviada a la RA")

def receive_device_id():
    """
    Simula la recepción del ID asignado por la RA.
    Lee el archivo de respuesta generado por la RA y guarda el ID localmente.
    """
    if not os.path.exists("data/ra_response.json"):
        print("[!] Aún no hay respuesta de la RA")
        return None

    with open("data/ra_response.json", "r") as f:
        data = json.load(f)
        device_id = data["device_id"]

    # Guardar el ID recibido en un archivo local
    with open("data/device_id.txt", "w") as f:
        f.write(device_id)

    print(f"[✓] Dispositivo recibió ID asignado: {device_id}")
    return device_id

# --------------------------------------------------------
# Flujo principal del script:
# 1. Generar claves ECC
# 2. Enviar solicitud de registro a la RA
# 3. Esperar confirmación de registro e ID
# --------------------------------------------------------
if __name__ == "__main__":
    key = generate_ecc_keys()                 # Paso 1: generar claves
    send_registration_request(key)            # Paso 2: solicitar registro
    input("Presiona ENTER una vez que la RA haya registrado y generado el ID...\n")
    receive_device_id()                       # Paso 3: recibir y guardar ID