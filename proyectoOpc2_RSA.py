#!/usr/bin/env python3
"""
Secure Communication Protocol Implementation
Proyecto de Criptografía - Implementación de protocolo de comunicación segura
para dispositivos IoT con recursos limitados
"""

import os
import json
import time
import hashlib
import secrets
from datetime import datetime
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
import base64 


# CONFIGURACIÓN Y CONSTANTES

class Config:
    """Configuración del sistema de comunicación segura"""
    RSA_KEY_SIZE = 2048
    AES_KEY_SIZE = 32  # 256 bits
    AES_NONCE_SIZE = 12  # 96 bits para GCM
    HMAC_KEY_SIZE = 32
    SESSION_TIMEOUT = 3600  # 1 hora
    MAX_MESSAGE_SIZE = 4096


# ESTRUCTURAS DE DATOS

@dataclass
class DeviceInfo:
    """Información del dispositivo registrado"""
    device_id: str
    public_key: str
    registration_time: str
    status: str = "active"

@dataclass
class SessionInfo:
    """Información de la sesión segura"""
    session_id: str
    device_id: str
    session_key: bytes
    created_at: float
    last_activity: float
    authenticated: bool = False

@dataclass
class SecureMessage:
    """Estructura de mensaje seguro"""
    sender_id: str
    recipient_id: str
    encrypted_data: str
    hmac: str
    nonce: str
    timestamp: float
# UTILIDADES CRIPTOGRÁFICAS

class CryptoUtils:
    """Utilidades criptográficas para el protocolo"""
    
    @staticmethod
    def generate_rsa_keypair() -> Tuple[bytes, bytes]:
        """Genera un par de claves RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=Config.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

    @staticmethod
    def rsa_encrypt(data: bytes, public_key_pem: bytes) -> bytes:
        """Cifra datos con RSA-OAEP"""
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def rsa_decrypt(encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """Descifra datos con RSA-OAEP"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def generate_session_key() -> bytes:
        """Genera una clave de sesión AES aleatoria"""
        return secrets.token_bytes(Config.AES_KEY_SIZE)
    @staticmethod
    def aes_gcm_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Cifra datos usando AES-GCM"""
        nonce = secrets.token_bytes(Config.AES_NONCE_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + encryptor.tag, nonce

    @staticmethod
    def aes_gcm_decrypt(encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Descifra datos usando AES-GCM"""
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def calculate_hmac(data: bytes, key: bytes) -> bytes:
        """Calcula HMAC-SHA256"""
        h = HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    @staticmethod
    def verify_hmac(data: bytes, key: bytes, expected_hmac: bytes) -> bool:
        """Verifica HMAC-SHA256"""
        try:
            h = HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            h.verify(expected_hmac)
            return True
        except Exception:
            return False

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """Calcula hash SHA-256"""
        return hashlib.sha256(data).hexdigest()
# AUTORIDAD DE REGISTRO (RA)

class RegistrationAuthority:
    """Autoridad de Registro para gestión de dispositivos"""
    
    def __init__(self):
        self.registered_devices: Dict[str, DeviceInfo] = {}
        self.device_certificates: Dict[str, bytes] = {}
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        
    def register_device(self, public_key_pem: bytes) -> str:
        """Registra un nuevo dispositivo y devuelve su ID"""
        device_id = f"DEV_{int(time.time())}{secrets.randbelow(1000):03d}"
        
        device_info = DeviceInfo(
            device_id=device_id,
            public_key=base64.b64encode(public_key_pem).decode(),
            registration_time=datetime.now().isoformat(),
            status="active"
        )
        
        self.registered_devices[device_id] = device_info
        self.device_certificates[device_id] = public_key_pem
        
        print(f"[RA] Dispositivo registrado: {device_id}")
        return device_id
    
    def verify_device(self, device_id: str) -> Optional[DeviceInfo]:
        """Verifica si un dispositivo está registrado"""
        return self.registered_devices.get(device_id)
    
    def get_device_public_key(self, device_id: str) -> Optional[bytes]:
        """Obtiene la clave pública de un dispositivo"""
        return self.device_certificates.get(device_id)
    
    def revoke_device(self, device_id: str) -> bool:
        """Revoca el registro de un dispositivo"""
        if device_id in self.registered_devices:
            self.registered_devices[device_id].status = "revoked"
            print(f"[RA] Dispositivo revocado: {device_id}")
            return True
        return False
# SIMULADOR DE DISPOSITIVO IoT

class IoTDevice:
    """Simulador de dispositivo IoT con recursos limitados"""
    
    def __init__(self, device_type: str = "smartwatch"):
        self.device_type = device_type
        self.device_id: Optional[str] = None
        self.private_key: Optional[bytes] = None
        self.public_key: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.session_id: Optional[str] = None
        self.registered = False
        self.authenticated = False
        
        # Simular limitaciones de recursos
        self.max_operations_per_second = 10
        self.max_memory_usage = 1024 * 1024  # 1MB
    
    def generate_keys(self):
        """Genera par de claves RSA (simulando proceso lento)"""
        print(f"[DEVICE] Generando claves RSA (simulando dispositivo limitado)...")
        time.sleep(1)  # Simular tiempo de procesamiento
        
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        print(f"[DEVICE] Claves generadas exitosamente")
    
    def register_with_ra(self, ra: RegistrationAuthority) -> bool:
        """Se registra con la Autoridad de Registro"""
        if not self.public_key:
            print("[DEVICE] Error: No hay clave pública generada")
            return False
        
        print("[DEVICE] Iniciando registro con RA...")
        self.device_id = ra.register_device(self.public_key)
        self.registered = True
        print(f"[DEVICE] Registro exitoso. ID asignado: {self.device_id}")
        return True
    def initiate_secure_session(self, server: 'ApplicationServer') -> bool:
        """Inicia sesión segura con el servidor"""
        if not self.registered:
            print("[DEVICE] Error: Dispositivo no registrado")
            return False
        
        print("[DEVICE] Iniciando protocolo de autenticación...")
        
        auth_request = {
            "device_id": self.device_id,
            "timestamp": time.time(),
            "challenge": secrets.token_hex(16)
        }
        
        response = server.handle_auth_request(auth_request)
        if not response["success"]:
            print(f"[DEVICE] Error de autenticación: {response['error']}")
            return False
        
        session_key_encrypted = base64.b64decode(response["session_key"])
        self.session_key = CryptoUtils.rsa_decrypt(session_key_encrypted, self.private_key)
        self.session_id = response["session_id"]
        self.authenticated = True
        
        print("[DEVICE] Autenticación exitosa. Sesión segura establecida.")
        return True

    def send_secure_message(self, message: str, server: 'ApplicationServer') -> bool:
        """Envía mensaje cifrado al servidor"""
        if not self.authenticated:
            print("[DEVICE] Error: Sesión no autenticada")
            return False
        
        print(f"[DEVICE] Enviando mensaje seguro: '{message}'")
        
        message_bytes = message.encode('utf-8')
        encrypted_data, nonce = CryptoUtils.aes_gcm_encrypt(message_bytes, self.session_key)
        hmac = CryptoUtils.calculate_hmac(encrypted_data + nonce, self.session_key)
        
        secure_message = SecureMessage(
            sender_id=self.device_id,
            recipient_id="SERVER",
            encrypted_data=base64.b64encode(encrypted_data).decode(),
            hmac=base64.b64encode(hmac).decode(),
            nonce=base64.b64encode(nonce).decode(),
            timestamp=time.time()
        )
        
        return server.receive_secure_message(secure_message)


# SERVIDOR DE APLICACIÓN

class ApplicationServer:
    """Servidor de aplicación para manejar dispositivos IoT"""
    
    def __init__(self, ra: RegistrationAuthority):
        self.ra = ra
        self.server_id = "APP_SERVER_001"
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        self.active_sessions: Dict[str, SessionInfo] = {}
        self.message_log: list = []
        
        print(f"[SERVER] Servidor inicializado: {self.server_id}")
    
    def handle_auth_request(self, auth_request: Dict) -> Dict:
        """Maneja solicitud de autenticación de dispositivo"""
        device_id = auth_request["device_id"]
        device_info = self.ra.verify_device(device_id)
        if not device_info or device_info.status != "active":
            return {"success": False, "error": "Dispositivo no autorizado"}
        
        print(f"[SERVER] Autenticando dispositivo: {device_id}")
        
        session_key = CryptoUtils.generate_session_key()
        session_id = f"SES_{int(time.time())}{secrets.randbelow(1000):03d}"
        
        device_public_key = self.ra.get_device_public_key(device_id)
        encrypted_session_key = CryptoUtils.rsa_encrypt(session_key, device_public_key)
        
        session = SessionInfo(
            session_id=session_id,
            device_id=device_id,
            session_key=session_key,
            created_at=time.time(),
            last_activity=time.time(),
            authenticated=True
        )
        
        self.active_sessions[session_id] = session
        print(f"[SERVER] Sesión establecida: {session_id}")
        
        return {
            "success": True,
            "session_id": session_id,
            "session_key": base64.b64encode(encrypted_session_key).decode(),
            "server_public_key": base64.b64encode(self.public_key).decode()
        }

    def receive_secure_message(self, secure_message: SecureMessage) -> bool:
        """Recibe y procesa mensaje seguro"""
        session = next((s for s in self.active_sessions.values() if s.device_id == secure_message.sender_id), None)
        if not session:
            print("[SERVER] Error: Sesión no encontrada")
            return False
        
        try:
            encrypted_data = base64.b64decode(secure_message.encrypted_data)
            nonce = base64.b64decode(secure_message.nonce)
            received_hmac = base64.b64decode(secure_message.hmac)
            
            if not CryptoUtils.verify_hmac(encrypted_data + nonce, session.session_key, received_hmac):
                print("[SERVER] Error: HMAC inválido - mensaje comprometido")
                return False
            
            decrypted_data = CryptoUtils.aes_gcm_decrypt(encrypted_data, session.session_key, nonce)
            message = decrypted_data.decode('utf-8')
            
            print(f"[SERVER] Mensaje recibido de {secure_message.sender_id}: '{message}'")
            self.message_log.append({
                "timestamp": secure_message.timestamp,
                "sender": secure_message.sender_id,
                "message": message,
                "session_id": session.session_id
            })
            
            session.last_activity = time.time()
            self._send_response(session, f"Echo: {message} [Timestamp: {datetime.now().isoformat()}]")
            return True
            
        except Exception as e:
            print(f"[SERVER] Error procesando mensaje: {str(e)}")
            return False

    def _send_response(self, session: SessionInfo, message: str):
        """Envía respuesta cifrada al dispositivo"""
        message_bytes = message.encode('utf-8')
        encrypted_data, nonce = CryptoUtils.aes_gcm_encrypt(message_bytes, session.session_key)
        hmac = CryptoUtils.calculate_hmac(encrypted_data + nonce, session.session_key)
        print(f"[SERVER] Enviando respuesta cifrada a {session.device_id}: '{message}'")

    def cleanup_expired_sessions(self):
        """Limpia sesiones expiradas"""
        now = time.time()
        expired = [sid for sid, s in self.active_sessions.items() if now - s.last_activity > Config.SESSION_TIMEOUT]
        for sid in expired:
            del self.active_sessions[sid]
            print(f"[SERVER] Sesión expirada eliminada: {sid}")


# DEMOSTRACIÓN DEL PROTOCOLO

def demonstrate_protocol():
    print("=" * 80)
    print("DEMOSTRACIÓN DEL PROTOCOLO DE COMUNICACIÓN SEGURA")
    print("Implementación para dispositivos IoT con recursos limitados")
    print("=" * 80)

    print("\n1. INICIALIZACIÓN DEL SISTEMA")
    print("-" * 40)
    ra = RegistrationAuthority()
    server = ApplicationServer(ra)
    device = IoTDevice("smartwatch")

    print("\n2. FASE DE REGISTRO")
    print("-" * 40)
    device.generate_keys()
    device.register_with_ra(ra)

    print("\n3. ESTABLECIMIENTO DE SESIÓN SEGURA")
    print("-" * 40)
    if not device.initiate_secure_session(server):
        print("[SISTEMA] Error en protocolo de autenticación")
        return

    print("\n4. INTERCAMBIO DE MENSAJES SEGUROS")
    print("-" * 40)
    for msg in [
        "Mensaje de Prueba",
        "Sensor: Temperatura 23.5°C",
        "Bateria: 85%",

    ]:
        if device.send_secure_message(msg, server):
            print("[SISTEMA] Mensaje enviado y procesado correctamente")
        else:
            print("[SISTEMA] Error enviando mensaje")
        time.sleep(0.5)

    print("\n5. RESUMEN DE LA SESIÓN")
    print("-" * 40)
    print(f"Dispositivos registrados: {len(ra.registered_devices)}")
    print(f"Sesiones activas: {len(server.active_sessions)}")
    print(f"Mensajes intercambiados: {len(server.message_log)}")
    for entry in server.message_log:
        timestamp = datetime.fromtimestamp(entry["timestamp"]).strftime("%H:%M:%S")
        print(f"[{timestamp}] {entry['sender']}: {entry['message']}")


def security_analysis():
    print("\n" + "-" * 80)
    print("Seguridad usada")
    print(" • RSA-2048 con OAEP")
    print(" • AES-256-GCM")
    print(" • HMAC-SHA256")
    print(" • SHA-256")
    print(" • HKDF")


if __name__ == "__main__":
    try:
        demonstrate_protocol()
        security_analysis()
    except KeyboardInterrupt:
        print("\n[SISTEMA] Demostración interrumpida por el usuario")
    except Exception as e:
        print(f"\n[ERROR] Error inesperado: {str(e)}")
        import traceback
        traceback.print_exc()
