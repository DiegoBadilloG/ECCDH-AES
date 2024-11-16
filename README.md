# Proyecto de Fin de Grado: Sistema de Cifrado de Alto Rendimiento

Este proyecto combina un sistema de cifrado avanzado que utiliza **AES (Advanced Encryption Standard)** en modo CTR y curvas elípticas (Curve25519 y secp256r1) para el intercambio seguro de claves. El sistema ha sido diseñado para operar tanto en simulación de hardware como en software, garantizando un entorno seguro y de alto rendimiento para el cifrado de datos.

## Estructura del Proyecto

El proyecto se organiza en dos grandes componentes, cada uno con su propia carpeta en el repositorio:

### 1. Componente de Software
Contiene las implementaciones de algoritmos y herramientas criptográficas necesarias para la simulación y pruebas de los sistemas de cifrado.

- **software/**: Carpeta principal de software.
  - **src/**: Código fuente del software.
    - **aes/**: Implementaciones de AES en modo CTR.
    - **dh/**: Implementaciones de curvas elípticas para el intercambio de claves Diffie-Hellman.
    - **kdf.py**: Función de derivación de claves.
    - **crypto_system.py**: Sistema criptográfico integrado con AES-CTR y DH.
    - **utils/**: Utilidades adicionales, incluyendo herramientas de prueba y validación.
    - **tests/**: Pruebas unitarias y de rendimiento.
    - **main.py**: Punto de entrada principal de la aplicación de software.

### 2. Componente de Hardware
Incluye los elementos necesarios para la simulación del sistema criptográfico en hardware, con implementaciones específicas del modo **AES-CTR** junto con las curvas **Curve25519** y **secp256r1**.

- **hardware/**: Carpeta principal del hardware.
  - **src/**: Código fuente para simulaciones de hardware.
    - **curve25519/**: Implementaciones de cifrado usando AES-CTR y ECC (Curve25519).
      - **AES_128_ctr/**: Implementación del modo AES-CTR con clave de 128 bits.
      - **ECCDH_AES128/**: Implementación de Diffie-Hellman combinada con AES-CTR de 128 bits.
      - **algorithm_25519/**: Algoritmo de la curva elíptica Curve25519.
      - **uart/**: Comunicación a través de UART para pruebas y simulación.
    - **curve256/**: Implementaciones de cifrado usando AES-CTR y ECC (secp256r1).
      - **AES_128_ctr/**: Implementación del modo AES-CTR con clave de 128 bits.
      - **Ecdh_AES128CTR/**: Implementación de ECDH con AES-CTR en 128 bits.
      - **Algorithm_256r1/**: Algoritmo de la curva elíptica secp256r1.
      - **uart/**: Comunicación a través de UART para pruebas y simulación.

## Requisitos

- **Software**: Python 3.10.12 o superior. Las dependencias están listadas en `requirements.txt`.
- **Hardware**: La simulación del componente de hardware se ha realizado utilizando **Vivado** de Xilinx.

## Instalación

1. **Instala las dependencias de software**:
   ```bash
   pip install -r requirements.txt

