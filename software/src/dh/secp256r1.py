
'''
Implementación de Criptografía de Curva Elíptica secp256r1 (NIST P-256)

Este módulo proporciona una implementación en Python puro de la curva elíptica secp256r1,
utilizada para el intercambio de claves Diffie-Hellman con Curva Elíptica (ECDH) y firmas
digitales. Incluye funciones para la suma de puntos, multiplicación escalar, generación
de pares de claves y cálculo de secreto compartido.
'''

import secrets
from typing import Tuple, Optional

# Parámetros de la curva
p: int = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a: int = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b: int = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx: int = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy: int = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G: Tuple[int, int] = (Gx, Gy)
n: int = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
h: int = 0x1

Punto = Tuple[int, int]
INFINITO: Punto = (0, 0)

def sumar_puntos(P: Punto, Q: Punto, a: int, p: int) -> Punto:
    
    # Suma dos puntos en la curva elíptica
    if P == INFINITO:
        return Q
    if Q == INFINITO:
        return P
    
    x_p, y_p = P
    x_q, y_q = Q
    
    if P == Q:  # Duplicación de punto
        if y_p == 0:
            return INFINITO
        s = ((3 * x_p**2 + a) * pow(2 * y_p, -1, p)) % p
    elif x_p == x_q:
        return INFINITO
    else:  # Suma de puntos
        s = ((y_q - y_p) * pow(x_q - x_p, -1, p)) % p
    
    x_r = (s**2 - x_p - x_q) % p
    y_r = (s * (x_p - x_r) - y_p) % p
    
    return (x_r, y_r)


def multiplicar_punto_por_escalar(punto: Punto, escalar: int, a: int, p: int) -> Punto:
    
    # Usando el algoritmo de doble y suma."""
    resultado = INFINITO
    actual = punto
    
    while escalar:
        if escalar & 1:
            resultado = sumar_puntos(resultado, actual, a, p)
        actual = sumar_puntos(actual, actual, a, p)
        escalar >>= 1
    
    return resultado


def esta_punto_en_curva(punto: Punto, a: int, b: int, p: int) -> bool:

    if punto == INFINITO:
        return True
    x, y = punto

    return (y**2 - x**3 - a * x - b) % p == 0


def generar_par_claves_secp256r1() -> Tuple[int, Punto]:

    clave_privada = secrets.randbelow(n - 1) + 1
    clave_publica = multiplicar_punto_por_escalar(G, clave_privada, a, p)

    return clave_privada, clave_publica


def calcular_secreto_compartido_secp256r1(clave_privada, clave_publica):

    if not isinstance(clave_privada, int):
        raise TypeError("La clave privada debe ser un entero")
    if not isinstance(clave_publica, tuple) or len(clave_publica) != 2:
        raise TypeError("La clave pública debe ser una tupla de dos elementos")
    if clave_privada <= 0 or clave_privada >= n:
        raise ValueError("La clave privada está fuera del rango válido")
    if clave_publica == (0, 0):
        raise ValueError("La clave pública no puede ser el punto en el infinito")
    if not esta_punto_en_curva(clave_publica, a, b, p):
        raise ValueError("La clave pública no está en la curva")
    punto_compartido = multiplicar_punto_por_escalar(clave_publica, clave_privada, a, p)

    return punto_compartido[0]  # Retornamos solo la coordenada x como secreto compartido


def validar_clave_publica(clave_publica: Punto) -> bool:
  
    if clave_publica == INFINITO:
        return False
    if not esta_punto_en_curva(clave_publica, a, b, p):
        return False
    if multiplicar_punto_por_escalar(clave_publica, n, a, p) != INFINITO:
        return False
    
    return True