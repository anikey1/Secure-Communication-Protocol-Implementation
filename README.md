# Secure Communication Protocol Implementation

Este proyecto implementa un protocolo de comunicación segura entre un dispositivo y un servidor, supervisado por una Autoridad de Registro (RA). Utiliza criptografía moderna para garantizar confidencialidad, integridad y autenticación mutua.

## Características

- Registro de dispositivos con RA
- Autenticación mutua con ECDSA (ECC + SHA-256)
- Derivación de clave con ECDH + HKDF (clave compartida)
- Cifrado simétrico autenticado con AES-GCM
- Implementación modular y portable

---

##  Requisitos

- Python 3.7 o superior
- Librería `cryptography`

---

## Instrucciones por sistema operativo

###  macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography
python proyectoCripto.py --run
```

###  Windows

```powershell
python -m venv venv
.env\Scriptsctivate
pip install cryptography
python proyectoCripto.py --run
```


---

Al correr el programa verás:
- Registro exitoso del dispositivo
- Firma verificada del servidor
- Clave de sesión derivada
- Mensaje cifrado y descifrado correctamente
- Confirmación de integridad y resistencia a ataques

---

##  Notas

- Este proyecto es didáctico y usa claves generadas al vuelo en memoria.
- No se usa almacenamiento persistente de claves salvo que se modifique explícitamente.
