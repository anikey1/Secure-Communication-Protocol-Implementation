# protocol.py
# --------------------------------------------------------
# Este módulo contiene funciones criptográficas comunes
# utilizadas tanto por el dispositivo como por el servidor.
#
# Funcionalidad:
# - Generación de nonces criptográficos
# - Firmas y verificación usando ECDSA (con SHA-256)
# - Derivación de claves de sesión con ECDH
# - Cifrado y descifrado de mensajes usando AES-GCM
# --------------------------------------------------------

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_nonce(size=16):
    """
    Genera un nonce criptográficamente seguro de tamaño 'size' bytes.
    Se usa para prevenir ataques de repetición en los protocolos.
    """
    return os.urandom(size)

def sign_data(private_key, data: bytes):
    """
    Firma digitalmente los datos con ECDSA y SHA-256.

    Parámetros:
        private_key: Clave privada ECC del firmante.
        data (bytes): Datos a firmar.

    Retorna:
        signature (bytes): Firma generada.
    """
    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

def verify_signature(public_key, signature: bytes, data: bytes):
    """
    Verifica una firma digital con la clave pública y los datos originales.

    Parámetros:
        public_key: Clave pública del firmante.
        signature (bytes): Firma recibida.
        data (bytes): Datos originales que se firmaron.

    Retorna:
        True si la firma es válida, False si falla.
    """
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False

def derive_shared_key(private_key, peer_public_key):
    """
    Realiza el intercambio de clave mediante ECDH (Elliptic Curve Diffie-Hellman)
    para derivar una clave compartida de sesión.

    Parámetros:
        private_key: Clave privada local.
        peer_public_key: Clave pública del otro participante.

    Retorna:
        shared_key (bytes): Clave secreta compartida derivada.
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key  # En producción, se usaría un KDF para fortalecer esta clave

def encrypt_message(session_key: bytes, plaintext: bytes):
    """
    Cifra un mensaje usando AES-GCM con autenticación integrada.

    Parámetros:
        session_key (bytes): Clave simétrica derivada vía ECDH.
        plaintext (bytes): Mensaje a cifrar.

    Retorna:
        nonce (bytes): Nonce aleatorio usado en el cifrado.
        ciphertext (bytes): Mensaje cifrado con autenticación.
    """
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)  # Tamaño estándar de nonce en AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_message(session_key: bytes, nonce: bytes, ciphertext: bytes):
    """
    Descifra un mensaje cifrado con AES-GCM.

    Parámetros:
        session_key (bytes): Clave de sesión compartida.
        nonce (bytes): Nonce utilizado durante el cifrado.
        ciphertext (bytes): Mensaje cifrado.

    Retorna:
        plaintext (bytes): Mensaje descifrado si la autenticación es válida.
    """
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
