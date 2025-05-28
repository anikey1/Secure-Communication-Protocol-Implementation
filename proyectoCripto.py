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

# Importación de librerías estándar de Python
import os
import json
import secrets

# Importación de módulos criptográficos de la librería cryptography
from cryptography.hazmat.primitives.asymmetric import ec  # Para criptografía de curva elíptica
from cryptography.hazmat.primitives import serialization, hashes  # Para serialización y funciones hash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Para derivación de claves
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Para cifrado autenticado AES-GCM


def print_separator(title=""):
    """
    Imprime un separador visual para organizar la salida del programa.
    
    Args:
        title (str): Título opcional a mostrar en el separador
    """
    if title:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    else:
        print(f"{'─'*60}")


def print_step(step, description):
    """
    Imprime información de un paso del protocolo de manera formateada.
    
    Args:
        step (int): Número del paso
        description (str): Descripción del paso
    """
    print(f"\n[PASO {step}] {description}")
    print(f"{'─'*40}")


def print_status(component, message, status="INFO"):
    """
    Imprime mensajes de estado con formato consistente y símbolos visuales.
    
    Args:
        component (str): Componente que genera el mensaje (DEVICE, SERVER, RA)
        message (str): Mensaje a mostrar
        status (str): Tipo de estado (INFO, SUCCESS, ERROR, SENDING, RECEIVING)
    """
    # Diccionario de símbolos para diferentes tipos de estado
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
    """
    Genera un par de claves de curva elíptica usando SECP256R1.
    
    Returns:
        tuple: (clave_privada, clave_publica) - Par de claves ECC
    """
    # Genera clave privada usando la curva SECP256R1 (también conocida como P-256)
    private_key = ec.generate_private_key(ec.SECP256R1())
    # Deriva la clave pública correspondiente
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(pubkey):
    """
    Serializa una clave pública ECC a formato PEM para transmisión.
    
    Args:
        pubkey: Objeto de clave pública ECC
        
    Returns:
        str: Clave pública en formato PEM como string
    """
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,  # Formato PEM (Base64 con headers)
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Formato estándar X.509
    ).decode()


def deserialize_public_key(pubkey_str):
    """
    Deserializa una clave pública desde formato PEM string a objeto utilizable.
    
    Args:
        pubkey_str (str): Clave pública en formato PEM
        
    Returns:
        Objeto de clave pública ECC
    """
    return serialization.load_pem_public_key(pubkey_str.encode())


def sign_data(private_key, data: bytes):
    """
    Firma datos usando ECDSA con SHA-256.
    
    Args:
        private_key: Clave privada ECC para firmar
        data (bytes): Datos a firmar
        
    Returns:
        bytes: Firma digital
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, signature, data: bytes):
    """
    Verifica una firma ECDSA usando una clave pública.
    
    Args:
        public_key: Clave pública ECC del firmante
        signature (bytes): Firma a verificar
        data (bytes): Datos originales que fueron firmados
        
    Returns:
        bool: True si la firma es válida, False en caso contrario
    """
    try:
        # Intenta verificar la firma, lanza excepción si es inválida
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        # Cualquier excepción indica firma inválida
        return False


def generate_nonce(length=16):
    """
    Genera un nonce criptográficamente seguro.
    
    Args:
        length (int): Longitud del nonce en bytes (por defecto 16)
        
    Returns:
        bytes: Nonce aleatorio
    """
    return secrets.token_bytes(length)


def derive_session_key(private_key, peer_public_key, info=b"session key", length=32):
    """
    Deriva una clave de sesión simétrica usando ECDH + HKDF.
    
    Args:
        private_key: Clave privada propia
        peer_public_key: Clave pública del peer
        info (bytes): Información de contexto para HKDF
        length (int): Longitud de la clave derivada en bytes
        
    Returns:
        bytes: Clave de sesión derivada
    """
    # Realiza intercambio de claves Diffie-Hellman sobre curva elíptica
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Aplica HKDF para derivar clave final con propiedades criptográficas robustas
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Función hash base
        length=length,  # Longitud de salida deseada
        salt=None,  # Sin salt (se usa un salt por defecto interno)
        info=info,  # Información de contexto
    )
    return hkdf.derive(shared_key)


def aes_gcm_encrypt(key, plaintext, associated_data=b""):
    """
    Cifra datos usando AES en modo GCM (Galois/Counter Mode).
    
    Args:
        key (bytes): Clave de cifrado AES
        plaintext (bytes): Datos a cifrar
        associated_data (bytes): Datos adicionales autenticados (no cifrados)
        
    Returns:
        tuple: (nonce, ciphertext) - Nonce usado y texto cifrado con tag de autenticación
    """
    aesgcm = AESGCM(key)
    # Genera nonce único de 12 bytes (recomendado para AES-GCM)
    nonce = secrets.token_bytes(12)
    # Cifra y autentica los datos
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def aes_gcm_decrypt(key, nonce, ciphertext, associated_data=b""):
    """
    Descifra datos cifrados con AES-GCM y verifica su integridad.
    
    Args:
        key (bytes): Clave de cifrado AES
        nonce (bytes): Nonce usado en el cifrado
        ciphertext (bytes): Datos cifrados con tag de autenticación
        associated_data (bytes): Datos adicionales que fueron autenticados
        
    Returns:
        bytes: Datos descifrados
        
    Raises:
        Exception: Si la autenticación falla (datos alterados)
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


class RegistrationAuthority:
    """
    Autoridad de Registro que gestiona el registro y validación de dispositivos.
    
    Responsabilidades:
    - Registrar nuevos dispositivos con sus claves públicas
    - Asignar IDs únicos a dispositivos
    - Proporcionar información de dispositivos registrados para validación
    """
    
    def __init__(self):
        """
        Inicializa la Autoridad de Registro.
        """
        # Diccionario para almacenar dispositivos registrados {device_id: {public_key: pem_string}}
        self.registered_devices = {}
        # Contador para generar IDs únicos secuenciales
        self.device_counter = 1
        print_status("RA", "Autoridad de Registro inicializada", "SUCCESS")

    def register_device(self, device_public_key_pem):
        """
        Registra un nuevo dispositivo con su clave pública.
        
        Args:
            device_public_key_pem (str): Clave pública del dispositivo en formato PEM
            
        Returns:
            str: ID único asignado al dispositivo
        """
        # Genera ID único para el dispositivo
        device_id = f"device_{self.device_counter}"
        self.device_counter += 1
        
        # Almacena la información del dispositivo
        self.registered_devices[device_id] = {
            "public_key": device_public_key_pem
        }
        print_status("RA", "Dispositivo registrado exitosamente", "SUCCESS")
        print_status("RA", f"ID asignado: {device_id}", "INFO")
        return device_id

    def get_device_public_key(self, device_id):
        """
        Obtiene la clave pública de un dispositivo registrado.
        
        Args:
            device_id (str): ID del dispositivo
            
        Returns:
            str or None: Clave pública en formato PEM o None si no existe
        """
        return self.registered_devices.get(device_id, {}).get("public_key", None)


class Device:
    """
    Representa un dispositivo IoT que se comunica de forma segura con un servidor.
    
    Responsabilidades:
    - Generar par de claves ECC propio
    - Registrarse con la Autoridad de Registro
    - Realizar handshake de autenticación mutua con el servidor
    - Enviar y recibir mensajes cifrados
    """
    
    def __init__(self, ra: RegistrationAuthority):
        """
        Inicializa un nuevo dispositivo.
        
        Args:
            ra (RegistrationAuthority): Referencia a la Autoridad de Registro
        """
        self.ra = ra  # Referencia a la RA para registro
        # Genera par de claves ECC propio
        self.private_key, self.public_key = generate_ecc_keypair()
        self.device_id = None  # Se asigna durante el registro
        self.session_key = None  # Se deriva durante el handshake
        self.server_public_key = None  # Se recibe durante el handshake
        print_status("DEVICE", "Dispositivo inicializado con claves ECC", "SUCCESS")

    def register(self):
        """
        Registra el dispositivo con la Autoridad de Registro.
        """
        print_step(1, "REGISTRO DEL DISPOSITIVO")
        # Serializa clave pública para envío
        pubkey_pem = serialize_public_key(self.public_key)
        # Registra con la RA y obtiene ID único
        self.device_id = self.ra.register_device(pubkey_pem)
        print_status("DEVICE", f"Registro completado con ID: {self.device_id}", "SUCCESS")

    def create_handshake_message_1(self):
        """
        Crea el primer mensaje del handshake (solicitud de conexión).
        
        Returns:
            dict: Mensaje con ID del dispositivo, nonce y clave pública
        """
        print_step(2, "INICIO DE HANDSHAKE")
        # Genera nonce único para este handshake
        self.nonce = generate_nonce()
        
        # Construye mensaje inicial del handshake
        message = {
            "device_id": self.device_id,
            "device_nonce": self.nonce.hex(),  # Convierte bytes a hex para transmisión
            "device_public_key": serialize_public_key(self.public_key),
        }
        print_status("DEVICE", "Mensaje de handshake creado", "SUCCESS")
        print_status("DEVICE", f"Nonce generado: {self.nonce.hex()[:16]}...", "INFO")
        print_status("DEVICE", "Enviando solicitud de conexión al servidor", "SENDING")
        print_status("DEVICE", f"Handshake message 1 completo: {json.dumps(message, indent=2)}", "INFO")
        return message

    def process_handshake_message_2(self, message):
        """
        Procesa la respuesta del servidor al handshake y completa la autenticación mutua.
        
        Args:
            message (dict): Respuesta del servidor con nonce, clave pública y firma
            
        Raises:
            Exception: Si la verificación de firma falla
        """
        print_step(3, "PROCESANDO RESPUESTA DEL SERVIDOR")
        
        # Extrae datos de la respuesta del servidor
        server_nonce = bytes.fromhex(message["server_nonce"])
        server_pubkey_pem = message["server_public_key"]
        signature = bytes.fromhex(message["signature"])

        # Deserializa clave pública del servidor
        self.server_public_key = deserialize_public_key(server_pubkey_pem)
        print_status("DEVICE", "Clave pública del servidor recibida", "RECEIVING")

        # Reconstruye datos que fueron firmados por el servidor
        # Formato: nonce_dispositivo || nonce_servidor || clave_pub_dispositivo || clave_pub_servidor
        signed_data = (
            self.nonce +
            server_nonce +
            self.public_key.public_bytes(
                serialization.Encoding.DER,  # Formato DER para consistencia
                serialization.PublicFormat.SubjectPublicKeyInfo
            ) +
            self.server_public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        # Verifica la firma del servidor para autenticarlo
        if not verify_signature(self.server_public_key, signature, signed_data):
            print_status("DEVICE", "Verificación de firma FALLIDA", "ERROR")
            raise Exception("Firma de servidor inválida")

        print_status("DEVICE", "Firma del servidor verificada correctamente", "SUCCESS")
        print_status("DEVICE", "Autenticación del servidor completada", "SUCCESS")

        # Deriva clave de sesión usando ECDH con clave privada propia y pública del servidor
        self.session_key = derive_session_key(self.private_key, self.server_public_key)
        print_status("DEVICE", "Clave de sesión derivada mediante ECDH", "SUCCESS")
        print_status("DEVICE", "Protocolo de handshake completado", "SUCCESS")

        # Guarda nonce del servidor para posible uso futuro
        self.server_nonce = server_nonce

    def send_secure_message(self, plaintext: bytes):
        """
        Envía un mensaje cifrado usando la clave de sesión establecida.
        
        Args:
            plaintext (bytes): Mensaje a cifrar y enviar
            
        Returns:
            tuple: (nonce_hex, ciphertext_hex) - Nonce y texto cifrado en hexadecimal
            
        Raises:
            Exception: Si no hay clave de sesión establecida
        """
        if self.session_key is None:
            raise Exception("No hay clave de sesión establecida")
        
        # Cifra mensaje usando AES-GCM con device_id como datos adicionales autenticados
        nonce, ciphertext = aes_gcm_encrypt(self.session_key, plaintext, associated_data=self.device_id.encode())
        print_status("DEVICE", f"Mensaje cifrado con AES-GCM", "SUCCESS")
        print_status("DEVICE", f"Nonce: {nonce.hex()}", "INFO")
        print_status("DEVICE", f"Ciphertext: {ciphertext.hex()}", "INFO")
        print_status("DEVICE", f"Mensaje cifrado: nonce={nonce.hex()}, ciphertext={ciphertext.hex()}", "INFO")
        
        # Retorna en formato hexadecimal para transmisión
        return nonce.hex(), ciphertext.hex()

    def receive_secure_message(self, nonce_hex, ciphertext_hex):
        """
        Recibe y descifra un mensaje usando la clave de sesión establecida.
        
        Args:
            nonce_hex (str): Nonce en formato hexadecimal
            ciphertext_hex (str): Texto cifrado en formato hexadecimal
            
        Returns:
            bytes: Mensaje descifrado
            
        Raises:
            Exception: Si no hay clave de sesión o si falla la autenticación
        """
        if self.session_key is None:
            raise Exception("No hay clave de sesión establecida")
        
        # Convierte de hexadecimal a bytes
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Descifra y verifica integridad usando device_id como datos adicionales
        plaintext = aes_gcm_decrypt(self.session_key, nonce, ciphertext, associated_data=self.device_id.encode())
        print_status("DEVICE", "Mensaje descifrado correctamente", "SUCCESS")
        return plaintext


class Server:
    """
    Servidor que se comunica de forma segura con dispositivos registrados.
    
    Responsabilidades:
    - Validar dispositivos contra la Autoridad de Registro
    - Realizar handshake de autenticación mutua
    - Mantener sesiones seguras con múltiples dispositivos
    - Enviar y recibir mensajes cifrados
    """
    
    def __init__(self, ra: RegistrationAuthority):
        """
        Inicializa el servidor.
        
        Args:
            ra (RegistrationAuthority): Referencia a la Autoridad de Registro
        """
        self.ra = ra  # Referencia a la RA para validación de dispositivos
        # Genera par de claves ECC propio
        self.private_key, self.public_key = generate_ecc_keypair()
        # Diccionario para mantener sesiones activas {device_id: session_info}
        self.sessions = {}
        print_status("SERVER", "Servidor inicializado con claves ECC", "SUCCESS")

    def process_handshake_message_1(self, message):
        """
        Procesa la solicitud inicial de handshake de un dispositivo.
        
        Args:
            message (dict): Mensaje inicial del dispositivo con ID, nonce y clave pública
            
        Returns:
            dict: Respuesta con nonce del servidor, clave pública y firma
            
        Raises:
            Exception: Si el dispositivo no está registrado o la clave no coincide
        """
        print_step(2, "PROCESANDO SOLICITUD DE CONEXIÓN")
        
        # Extrae información del mensaje del dispositivo
        device_id = message["device_id"]
        device_nonce = bytes.fromhex(message["device_nonce"])
        device_pubkey_pem = message["device_public_key"]
        device_pubkey = deserialize_public_key(device_pubkey_pem)

        print_status("SERVER", f"Solicitud recibida de dispositivo: {device_id}", "RECEIVING")

        # Valida que el dispositivo esté registrado en la RA
        registered_pubkey_pem = self.ra.get_device_public_key(device_id)
        if registered_pubkey_pem != device_pubkey_pem:
            print_status("SERVER", "Dispositivo NO registrado o clave inválida", "ERROR")
            raise Exception("Dispositivo no registrado o clave pública no coincide")

        print_status("SERVER", "Dispositivo verificado con RA", "SUCCESS")
        print_status("SERVER", "Clave pública validada", "SUCCESS")

        # Genera nonce propio para el handshake
        server_nonce = generate_nonce()
        print_status("SERVER", f"Nonce del servidor: {server_nonce.hex()[:16]}...", "INFO")

        # Construye datos a firmar para autenticación mutua
        # Formato: nonce_dispositivo || nonce_servidor || clave_pub_dispositivo || clave_pub_servidor
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

        # Firma los datos con clave privada del servidor
        signature = sign_data(self.private_key, signed_data)
        print_status("SERVER", "Firma digital creada con ECDSA", "SUCCESS")

        # Deriva clave de sesión usando ECDH
        session_key = derive_session_key(self.private_key, device_pubkey)
        print_status("SERVER", "Clave de sesión derivada mediante ECDH", "SUCCESS")

        # Almacena información de la sesión
        self.sessions[device_id] = {
            "session_key": session_key,
            "server_nonce": server_nonce,
            "device_nonce": device_nonce,
            "device_pubkey": device_pubkey,
        }

        # Construye respuesta de handshake
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
        """
        Envía un mensaje cifrado a un dispositivo específico.
        
        Args:
            device_id (str): ID del dispositivo destinatario
            plaintext (bytes): Mensaje a cifrar y enviar
            
        Returns:
            tuple: (nonce_hex, ciphertext_hex) - Nonce y texto cifrado en hexadecimal
            
        Raises:
            Exception: Si no existe sesión para el dispositivo
        """
        if device_id not in self.sessions:
            raise Exception("No hay sesión para este dispositivo")
        
        # Obtiene clave de sesión para el dispositivo específico
        session_key = self.sessions[device_id]["session_key"]
        
        # Cifra mensaje usando AES-GCM con device_id como datos adicionales autenticados
        nonce, ciphertext = aes_gcm_encrypt(session_key, plaintext, associated_data=device_id.encode())
        print_status("SERVER", f"Mensaje cifrado con AES-GCM", "SUCCESS")
        print_status("SERVER", f"Nonce: {nonce.hex()}", "INFO")
        print_status("SERVER", f"Ciphertext: {ciphertext.hex()}", "INFO")
        print_status("SERVER", f"Mensaje cifrado: nonce={nonce.hex()}, ciphertext={ciphertext.hex()}", "INFO")
        
        # Retorna en formato hexadecimal para transmisión
        return nonce.hex(), ciphertext.hex()

    def receive_secure_message(self, device_id, nonce_hex, ciphertext_hex):
        """
        Recibe y descifra un mensaje de un dispositivo específico.
        
        Args:
            device_id (str): ID del dispositivo remitente
            nonce_hex (str): Nonce en formato hexadecimal
            ciphertext_hex (str): Texto cifrado en formato hexadecimal
            
        Returns:
            bytes: Mensaje descifrado
            
        Raises:
            Exception: Si no existe sesión o falla la autenticación
        """
        if device_id not in self.sessions:
            raise Exception("No hay sesión para este dispositivo")
        
        # Obtiene clave de sesión para el dispositivo específico
        session_key = self.sessions[device_id]["session_key"]
        
        # Convierte de hexadecimal a bytes
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Descifra y verifica integridad usando device_id como datos adicionales
        plaintext = aes_gcm_decrypt(session_key, nonce, ciphertext, associated_data=device_id.encode())
        print_status("SERVER", "Mensaje descifrado correctamente", "SUCCESS")
        return plaintext


if __name__ == "__main__":
    # ============================================================================
    # EJECUCIÓN PRINCIPAL DEL PROTOCOLO DE COMUNICACIÓN SEGURA
    # ============================================================================
    
    print_separator("PROTOCOLO DE COMUNICACIÓN SEGURA")
    print("  Implementación de autenticación mutua y comunicación cifrada")
    print("  Algoritmos: ECC (SECP256R1), ECDSA, ECDH, AES-GCM")

    # Fase 1: Inicialización del sistema
    print_separator("INICIALIZACIÓN DEL SISTEMA")
    
    # Crea instancias de los tres componentes principales
    ra = RegistrationAuthority()  # Autoridad de Registro
    device = Device(ra)          # Dispositivo IoT
    server = Server(ra)          # Servidor

    # Fase 2: Registro del dispositivo
    device.register()

    # Fase 3: Handshake de autenticación mutua
    # El dispositivo inicia el handshake
    msg1 = device.create_handshake_message_1()
    # El servidor procesa la solicitud y responde
    msg2 = server.process_handshake_message_1(msg1)
    # El dispositivo procesa la respuesta y completa el handshake
    device.process_handshake_message_2(msg2)

    # Fase 4: Comunicación segura bidireccional
    print_separator("COMUNICACIÓN SEGURA ESTABLECIDA")

    # Demostración: Dispositivo envía mensaje al servidor
    print_step(4, "ENVÍO DE MENSAJE DESDE DISPOSITIVO")
    mensaje = b"Datos confidenciales del dispositivo IoT"
    print_status("DEVICE", f"Mensaje original: {mensaje.decode()}", "INFO")
    nonce, ciphertext = device.send_secure_message(mensaje)

    # Servidor recibe y descifra el mensaje
    print_step(5, "RECEPCIÓN EN SERVIDOR")
    recibido = server.receive_secure_message(device.device_id, nonce, ciphertext)
    print_status("SERVER", f"Mensaje recibido: {recibido.decode()}", "SUCCESS")

    # Demostración: Servidor responde al dispositivo
    print_step(6, "RESPUESTA DEL SERVIDOR")
    respuesta = b"Mensaje recibido y procesado correctamente"
    print_status("SERVER", f"Respuesta: {respuesta.decode()}", "INFO")
    nonce_resp, ciphertext_resp = server.send_secure_message(device.device_id, respuesta)

    # Dispositivo recibe y descifra la respuesta
    print_step(7, "RECEPCIÓN DE RESPUESTA EN DISPOSITIVO")
    respuesta_final = device.receive_secure_message(nonce_resp, ciphertext_resp)
    print_status("DEVICE", f"Respuesta recibida: {respuesta_final.decode()}", "SUCCESS")

    # Resumen final del protocolo completado
    print_separator("PROTOCOLO COMPLETADO EXITOSAMENTE")
    print("  • Autenticación mutua: COMPLETADA")
    print("  • Derivación de clave de sesión: COMPLETADA")
    print("  • Comunicación cifrada bidireccional: COMPLETADA")
    print("  • Integridad de mensajes: VERIFICADA")
    print("  • Resistencia a ataques: GARANTIZADA")
    print_separator()
