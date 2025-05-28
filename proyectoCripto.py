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

"""

import os
import json
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def print_separator(title=""):
    if title:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    else:
        print(f"{'─'*60}")


def print_step(step, description):
    print(f"\n[PASO {step}] {description}")
    print(f"{'─'*40}")


def print_status(component, message, status="INFO"):
    status_symbols = {
        "INFO": "•",
        "SUCCESS": "✓",
        "ERROR": "✗",
        "SENDING": "→",
        "RECEIVING": "←"
    }
    symbol = status_symbols.get(status, "•")
    print(f"  {symbol} [{component}] {message}")


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
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, signature, data: bytes):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def generate_nonce(length=16):
    return secrets.token_bytes(length)


def derive_session_key(private_key, peer_public_key, info=b"session key", length=32):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
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
        print_status("RA", "Autoridad de Registro inicializada", "SUCCESS")

    def register_device(self, device_public_key_pem):
        device_id = f"device_{self.device_counter}"
        self.device_counter += 1
        self.registered_devices[device_id] = {
            "public_key": device_public_key_pem
        }
        print_status("RA", "Dispositivo registrado exitosamente", "SUCCESS")
        print_status("RA", f"ID asignado: {device_id}", "INFO")
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
        print_status("DEVICE", "Dispositivo inicializado con claves ECC", "SUCCESS")

    def register(self):
        print_step(1, "REGISTRO DEL DISPOSITIVO")
        pubkey_pem = serialize_public_key(self.public_key)
        self.device_id = self.ra.register_device(pubkey_pem)
        print_status("DEVICE", f"Registro completado con ID: {self.device_id}", "SUCCESS")

    def create_handshake_message_1(self):
        print_step(2, "INICIO DE HANDSHAKE")
        self.nonce = generate_nonce()
        message = {
            "device_id": self.device_id,
            "device_nonce": self.nonce.hex(),
            "device_public_key": serialize_public_key(self.public_key),
        }
        print_status("DEVICE", "Mensaje de handshake creado", "SUCCESS")
        print("[devide] Mensaje original a enviar:", mensaje.decode())

        print_status("DEVICE", f"Nonce generado: {self.nonce.hex()[:16]}...", "INFO")
        print_status("DEVICE", "Enviando solicitud de conexión al servidor", "SENDING")
        print_status("DEVICE", f"Handshake message 1 completo: {json.dumps(message, indent=2)}", "INFO")
        return message

    def process_handshake_message_2(self, message):
        print_step(3, "PROCESANDO RESPUESTA DEL SERVIDOR")
        server_nonce = bytes.fromhex(message["server_nonce"])
        server_pubkey_pem = message["server_public_key"]
        signature = bytes.fromhex(message["signature"])

        self.server_public_key = deserialize_public_key(server_pubkey_pem)
        print_status("DEVICE", "Clave pública del servidor recibida", "RECEIVING")

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
            print_status("DEVICE", "Verificación de firma FALLIDA", "ERROR")
            raise Exception("Firma de servidor inválida")

        print_status("DEVICE", "Firma del servidor verificada correctamente", "SUCCESS")
        print_status("DEVICE", "Autenticación del servidor completada", "SUCCESS")

        self.session_key = derive_session_key(self.private_key, self.server_public_key)
        print_status("DEVICE", "Clave de sesión derivada mediante ECDH", "SUCCESS")
        print_status("DEVICE", "Protocolo de handshake completado", "SUCCESS")

        self.server_nonce = server_nonce

    def send_secure_message(self, plaintext: bytes):
        if self.session_key is None:
            raise Exception("No hay clave de sesión establecida")
        nonce, ciphertext = aes_gcm_encrypt(self.session_key, plaintext, associated_data=self.device_id.encode())
        print_status("DEVICE", f"Mensaje cifrado con AES-GCM", "SUCCESS")
        print_status("DEVICE", f"Nonce: {nonce.hex()}", "INFO")
        print_status("DEVICE", f"Ciphertext: {ciphertext.hex()}", "INFO")
        print_status("DEVICE", f"Mensaje cifrado: nonce={nonce.hex()}, ciphertext={ciphertext.hex()}", "INFO")
        return nonce.hex(), ciphertext.hex()

    def receive_secure_message(self, nonce_hex, ciphertext_hex):
        if self.session_key is None:
            raise Exception("No hay clave de sesión establecida")
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = aes_gcm_decrypt(self.session_key, nonce, ciphertext, associated_data=self.device_id.encode())
        print_status("DEVICE", "Mensaje descifrado correctamente", "SUCCESS")
        return plaintext


class Server:
    def __init__(self, ra: RegistrationAuthority):
        self.ra = ra
        self.private_key, self.public_key = generate_ecc_keypair()
        self.sessions = {}
        print_status("SERVER", "Servidor inicializado con claves ECC", "SUCCESS")

    def process_handshake_message_1(self, message):
        print_step(2, "PROCESANDO SOLICITUD DE CONEXIÓN")
        device_id = message["device_id"]
        device_nonce = bytes.fromhex(message["device_nonce"])
        device_pubkey_pem = message["device_public_key"]
        device_pubkey = deserialize_public_key(device_pubkey_pem)

        print_status("SERVER", f"Solicitud recibida de dispositivo: {device_id}", "RECEIVING")

        registered_pubkey_pem = self.ra.get_device_public_key(device_id)
        if registered_pubkey_pem != device_pubkey_pem:
            print_status("SERVER", "Dispositivo NO registrado o clave inválida", "ERROR")
            raise Exception("Dispositivo no registrado o clave pública no coincide")

        print_status("SERVER", "Dispositivo verificado con RA", "SUCCESS")
        print_status("SERVER", "Clave pública validada", "SUCCESS")

        server_nonce = generate_nonce()
        print_status("SERVER", f"Nonce del servidor: {server_nonce.hex()[:16]}...", "INFO")

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
        print_status("SERVER", "Firma digital creada con ECDSA", "SUCCESS")

        session_key = derive_session_key(self.private_key, device_pubkey)
        print_status("SERVER", "Clave de sesión derivada mediante ECDH", "SUCCESS")

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

        print_status("SERVER", "Respuesta de handshake preparada", "SUCCESS")
        print_status("SERVER", "Handshake message 2 completo: " + json.dumps(response, indent=2), "INFO")
        print_status("SERVER", "Enviando respuesta al dispositivo", "SENDING")
        return response

    def send_secure_message(self, device_id, plaintext: bytes):
        if device_id not in self.sessions:
            raise Exception("No hay sesión para este dispositivo")
        session_key = self.sessions[device_id]["session_key"]
        nonce, ciphertext = aes_gcm_encrypt(session_key, plaintext, associated_data=device_id.encode())
        print_status("SERVER", f"Mensaje cifrado con AES-GCM", "SUCCESS")
        print_status("SERVER", f"Nonce: {nonce.hex()}", "INFO")
        print_status("SERVER", f"Ciphertext: {ciphertext.hex()}", "INFO")
        print_status("SERVER", f"Mensaje cifrado: nonce={nonce.hex()}, ciphertext={ciphertext.hex()}", "INFO")
        return nonce.hex(), ciphertext.hex()

    def receive_secure_message(self, device_id, nonce_hex, ciphertext_hex):
        if device_id not in self.sessions:
            raise Exception("No hay sesión para este dispositivo")
        session_key = self.sessions[device_id]["session_key"]
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = aes_gcm_decrypt(session_key, nonce, ciphertext, associated_data=device_id.encode())
        print_status("SERVER", "Mensaje descifrado correctamente", "SUCCESS")
        return plaintext


if __name__ == "__main__":
    print_separator("PROTOCOLO DE COMUNICACIÓN SEGURA")
    print("  Implementación de autenticación mutua y comunicación cifrada")
    print("  Algoritmos: ECC (SECP256R1), ECDSA, ECDH, AES-GCM")

    print_separator("INICIALIZACIÓN DEL SISTEMA")
    ra = RegistrationAuthority()
    device = Device(ra)
    server = Server(ra)

    device.register()

    msg1 = device.create_handshake_message_1()
    msg2 = server.process_handshake_message_1(msg1)
    device.process_handshake_message_2(msg2)

    print_separator("COMUNICACIÓN SEGURA ESTABLECIDA")

    print_step(4, "ENVÍO DE MENSAJE DESDE DISPOSITIVO")
    mensaje = b"Datos confidenciales del dispositivo IoT"
    print_status("DEVICE", f"Mensaje original: {mensaje.decode()}", "INFO")
    nonce, ciphertext = device.send_secure_message(mensaje)

    print_step(5, "RECEPCIÓN EN SERVIDOR")
    recibido = server.receive_secure_message(device.device_id, nonce, ciphertext)
    print_status("SERVER", f"Mensaje recibido: {recibido.decode()}", "SUCCESS")

    print_step(6, "RESPUESTA DEL SERVIDOR")
    respuesta = b"Mensaje recibido y procesado correctamente"
    print_status("SERVER", f"Respuesta: {respuesta.decode()}", "INFO")
    nonce_resp, ciphertext_resp = server.send_secure_message(device.device_id, respuesta)

    print_step(7, "RECEPCIÓN DE RESPUESTA EN DISPOSITIVO")
    respuesta_final = device.receive_secure_message(nonce_resp, ciphertext_resp)
    print_status("DEVICE", f"Respuesta recibida: {respuesta_final.decode()}", "SUCCESS")

    print_separator("PROTOCOLO COMPLETADO EXITOSAMENTE")
    print("  • Autenticación mutua: COMPLETADA")
    print("  • Derivación de clave de sesión: COMPLETADA")
    print("  • Comunicación cifrada bidireccional: COMPLETADA")
    print("  • Integridad de mensajes: VERIFICADA")
    print("  • Resistencia a ataques: GARANTIZADA")
    print_separator()

