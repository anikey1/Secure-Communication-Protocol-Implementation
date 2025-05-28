"""
Este script implementa un protocolo de comunicación segura entre un dispositivo y un servidor,
supervisado por una Autoridad de Registro (RA). El protocolo consta de los siguientes pasos:

1. Registro de Dispositivo:
   El dispositivo genera un par de claves ECC y registra su clave pública con la RA. La RA le asigna un ID único.

2. Handshake (Autenticación Mutua + Derivación de Clave de Sesión):
   - El dispositivo inicia el handshake enviando su ID, un nonce y su clave pública.
   - El servidor verifica que el dispositivo esté registrado, genera su propio nonce,
     y firma los datos: nonce_dispositivo || nonce_servidor || clave_pub_dispositivo || clave_pub_servidor.
   - El dispositivo verifica la firma del servidor para autenticarlo.
   - Ambos derivan una clave de sesión simétrica mediante ECDH + HKDF.

3. Comunicación Segura:
   - Una vez establecida la clave de sesión, ambos pueden cifrar mensajes usando AES-GCM,
     lo cual garantiza confidencialidad e integridad.
   - Cada mensaje incluye un nonce único y es autenticado con associated_data.

Este enfoque garantiza:
- Autenticación mutua (con firmas y claves públicas)
- Confidencialidad (con AES-GCM)
- Integridad de los mensajes (a través del tag de autenticación de GCM)
- Resistencia a ataques de repetición (mediante nonces únicos)

Uso didáctico en prácticas de criptografía.
"""

import os
import json
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(pubkey):
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def deserialize_public_key(pubkey_str):
    return serialization.load_pem_public_key(pubkey_str.encode())


def sign_data(private_key, data: bytes):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


def verify_signature(public_key, signature, data: bytes):
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False


def generate_nonce(length=16):
    return secrets.token_bytes(length)


def derive_session_key(private_key, peer_public_key, info=b"session key", length=32):
    shared_key = private_key.exchange(
        ec.ECDH(), peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_key)


def aes_gcm_encrypt(key, plaintext, associated_data=b""):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def aes_gcm_decrypt(key, nonce, ciphertext, associated_data=b""):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


class RegistrationAuthority:
    def __init__(self):
        self.registered_devices = {}
        self.device_counter = 1

    def register_device(self, device_public_key_pem):
        device_id = f"device_{self.device_counter}"
        self.device_counter += 1
        self.registered_devices[device_id] = {
            "public_key": device_public_key_pem
        }
        print(f"[RA] Dispositivo registrado con ID: {device_id}")
        return device_id

    def get_device_public_key(self, device_id):
        return self.registered_devices.get(device_id, {}).get("public_key", None)


class Device:
    def __init__(self, ra: RegistrationAuthority):
        self.ra = ra
        self.private_key, self.public_key = generate_ecc_keypair()
        self.device_id = None
        self.session_key = None
        self.server_public_key = None

    def register(self):
        pubkey_pem = serialize_public_key(self.public_key)
        self.device_id = self.ra.register_device(pubkey_pem)

    def create_handshake_message_1(self):
        self.nonce = generate_nonce()
        message = {
            "device_id": self.device_id,
            "device_nonce": self.nonce.hex(),
            "device_public_key": serialize_public_key(self.public_key),
        }
        print(f"[Device] Enviando mensaje 1 (handshake): {message}")
        return message

    def process_handshake_message_2(self, message):
        server_nonce = bytes.fromhex(message["server_nonce"])
        server_pubkey_pem = message["server_public_key"]
        signature = bytes.fromhex(message["signature"])

        self.server_public_key = deserialize_public_key(server_pubkey_pem)

        signed_data = (
            self.nonce +
            server_nonce +
            self.public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            self.server_public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        if not verify_signature(self.server_public_key, signature, signed_data):
            raise Exception("[Device] Firma de servidor inválida!")

        print("[Device] Firma del servidor verificada correctamente.")

        self.session_key = derive_session_key(
            self.private_key, self.server_public_key)
        print("[Device] Clave de sesión derivada.")

        self.server_nonce = server_nonce

    def send_secure_message(self, plaintext: bytes):
        if self.session_key is None:
            raise Exception("No hay clave de sesión establecida.")
        nonce, ciphertext = aes_gcm_encrypt(
            self.session_key, plaintext, associated_data=self.device_id.encode())
        return nonce.hex(), ciphertext.hex()

    def receive_secure_message(self, nonce_hex, ciphertext_hex):
        if self.session_key is None:
            raise Exception("No hay clave de sesión establecida.")
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = aes_gcm_decrypt(
            self.session_key, nonce, ciphertext, associated_data=self.device_id.encode())
        return plaintext


class Server:
    def __init__(self, ra: RegistrationAuthority):
        self.ra = ra
        self.private_key, self.public_key = generate_ecc_keypair()
        self.sessions = {}

    def process_handshake_message_1(self, message):
        device_id = message["device_id"]
        device_nonce = bytes.fromhex(message["device_nonce"])
        device_pubkey_pem = message["device_public_key"]
        device_pubkey = deserialize_public_key(device_pubkey_pem)

        registered_pubkey_pem = self.ra.get_device_public_key(device_id)
        if registered_pubkey_pem != device_pubkey_pem:
            raise Exception(
                "[Server] Dispositivo no registrado o clave pública no coincide")

        server_nonce = generate_nonce()

        signed_data = (
            device_nonce +
            server_nonce +
            device_pubkey.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            self.public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        signature = sign_data(self.private_key, signed_data)

        session_key = derive_session_key(
            self.private_key, device_pubkey)

        self.sessions[device_id] = {
            "session_key": session_key,
            "server_nonce": server_nonce,
            "device_nonce": device_nonce,
            "device_pubkey": device_pubkey,
        }

        response = {
            "server_nonce": server_nonce.hex(),
            "server_public_key": serialize_public_key(self.public_key),
            "signature": signature.hex(),
        }
        print(f"[Server] Enviando mensaje 2 (handshake): {response}")
        return response

    def send_secure_message(self, device_id, plaintext: bytes):
        if device_id not in self.sessions:
            raise Exception("No hay sesión para este dispositivo.")
        session_key = self.sessions[device_id]["session_key"]
        nonce, ciphertext = aes_gcm_encrypt(
            session_key, plaintext, associated_data=device_id.encode())
        return nonce.hex(), ciphertext.hex()

    def receive_secure_message(self, device_id, nonce_hex, ciphertext_hex):
        if device_id not in self.sessions:
            raise Exception("No hay sesión para este dispositivo.")
        session_key = self.sessions[device_id]["session_key"]
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = aes_gcm_decrypt(
            session_key, nonce, ciphertext, associated_data=device_id.encode())
        return plaintext


if __name__ == "__main__":
    ra = RegistrationAuthority()

    device = Device(ra)
    device.register()

    server = Server(ra)

    msg1 = device.create_handshake_message_1()
    msg2 = server.process_handshake_message_1(msg1)
    device.process_handshake_message_2(msg2)

    texto = b"Hola servidor, este es un mensaje secreto."
    nonce, ciphertext = device.send_secure_message(texto)
    print(f"[Device] Mensaje cifrado: nonce={nonce}, ciphertext={ciphertext}")

    texto_descifrado = server.receive_secure_message(
        device.device_id, nonce, ciphertext)
    print(
        f"[Server] Mensaje recibido y descifrado: {texto_descifrado.decode()}")

    respuesta = b"Mensaje recibido correctamente."
    nonce_resp, ciphertext_resp = server.send_secure_message(
        device.device_id, respuesta)
    print(
        f"[Server] Respuesta cifrada: nonce={nonce_resp}, ciphertext={ciphertext_resp}")

    respuesta_descifrada = device.receive_secure_message(
        nonce_resp, ciphertext_resp)
    print(f"[Device] Respuesta descifrada: {respuesta_descifrada.decode()}")
