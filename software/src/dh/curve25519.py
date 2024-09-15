
'''
Implementación del Intercambio de Claves Diffie-Hellman con Curva Elíptica (ECDH) Curve25519

Este módulo proporciona una implementación en Python puro de la curva elíptica Curve25519,
utilizada para el intercambio de claves Diffie-Hellman. Incluye funciones para la generación
de claves, el cálculo del secreto compartido y la función central X25519.

'''



import secrets
from typing import Tuple, ByteString

P: int = 2**255 - 19 # Orden del campo primo para Curve25519


def ajustar(n: int) -> int:

    # Ajusta un entero según la especificación X25519
    n &= ~7
    n |= 1 << 254
    n &= ~(1 << 255)

    return n


def escalera_montgomery(k: int, u: int) -> int:
    
    # Realiza el algoritmo de la escalera de Montgomery para la multiplicación escalar
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1

    for i in reversed(range(256)):
        kt = (k >> i) & 1
        x2, x3 = intercambio_condicional(kt, x2, x3)
        z2, z3 = intercambio_condicional(kt, z2, z3)
        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = (DA + CB) % P
        x3 = (x3 * x3) % P
        z3 = (DA - CB) % P
        z3 = (z3 * z3) % P
        z3 = (z3 * x1) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + 121665 * E % P)) % P
        x2, x3 = intercambio_condicional(kt, x2, x3)
        z2, z3 = intercambio_condicional(kt, z2, z3)

    return (x2 * pow(z2, P - 2, P)) % P


def intercambio_condicional(intercambiar: int, x2: int, x3: int) -> Tuple[int, int]:
    
    # Protege contra ataques de temporización
    dummy = intercambiar * (x2 ^ x3)
    x2 ^= dummy
    x3 ^= dummy

    return x2, x3


def x25519(k: ByteString, u: ByteString) -> bytes:

    # Realiza la función Diffie-Hellman X25519

    k_int = ajustar(int.from_bytes(k, 'little'))
    u_int = int.from_bytes(u, 'little')

    return escalera_montgomery(k_int, u_int).to_bytes(32, 'little')


def generar_par_claves_25519() -> Tuple[bytes, bytes]:

    clave_privada = secrets.token_bytes(32)
    clave_publica = x25519(clave_privada, (9).to_bytes(32, 'little'))

    return clave_privada, clave_publica


def calcular_secreto_compartido_25519(clave_privada: ByteString, clave_publica: ByteString) -> bytes:

    # Calcula el secreto compartido usando una clave privada y la clave pública del par
    if len(clave_privada) != 32 or len(clave_publica) != 32:
        raise ValueError("Tanto la clave privada como la pública deben tener 32 bytes de longitud")
    if clave_publica == b'\x00' * 32:
        raise ValueError("La clave pública con todos los bits en cero es inválida")
    
    # Aplicamos el ajuste a la clave privada antes de usarla
    clave_privada_ajustada = ajustar(int.from_bytes(clave_privada, 'little')).to_bytes(32, 'little')
    
    return x25519(clave_privada_ajustada, clave_publica)