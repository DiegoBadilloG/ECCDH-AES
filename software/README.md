# Implementación de AES y Curvas Elípticas

Este proyecto implementa el algoritmo AES (Advanced Encryption Standard) en sus modos ECB, CBC y CTR, así como las curvas elípticas Curve25519 y secp256r1 para el intercambio de claves Diffie-Hellman.

## Estructura del Proyecto

- `src/`: Contiene el código fuente del proyecto.
  - `aes/`: Implementaciones de AES en diferentes modos.
  - `dh/`: Implementaciones de curvas elípticas para Diffie-Hellman.
  - `kdf.py`: Función de derivación de claves.
  - `crypto_system.py`: Implementación de AES-CTR con DH.
  - `utils/`: Utilidades, incluyendo pruebas estadísticas.
- `tests/`: Contiene las pruebas unitarias y de rendimiento.
- `main.py`: Punto de entrada principal del proyecto.

## Requisitos

Python 3.10.12 o superior. Las dependencias se encuentran en el archivo `requirements.txt`.

## Instalación

1. Clona este repositorio: METER LINK
2. Instalar las dependencias: pip install -r requirements.txt

## Uso
Para ejecutar el programa principal: python3 main
Para ejecutar las pruebas: python -m test.x

## Características

- Implementación de AES en modos ECB, CBC y CTR.
- Implementación de curvas elípticas Curve25519 y secp256r1.
- Pruebas de rendimiento y seguridad, incluyendo pruebas estadísticas NIST.
- Sistema criptográfico integrado que combina intercambio de claves Diffie-Hellman, derivación de claves y cifrado AES.

## Contacto

Sofía Brotton Ruiz - [sofiabruiz1999@gmail.com]
Diego Badillo Goméz - [diegoabgomez@gmail.com]

Enlace del proyecto: https://github.com/DiegoBadilloG/ECCDH-AES/tree/main