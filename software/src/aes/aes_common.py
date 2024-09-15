"""
Este módulo implementa las operaciones fundamentales del algoritmo AES (Advanced Encryption Standard).
Incluye funciones para la sustitución de bytes, desplazamiento de filas, mezcla de columnas, y expansión de clave, 
esenciales para el cifrado y descifrado AES, además de añadir o quitar padding PKCS7.
"""

from typing import List

sbox: List[int] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

inv_sbox: List[int] = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i

rcon: List[int] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def sustituir_bytes(estado: List[int]) -> List[int]:
    #Realiza la sustitución de bytes en el estado.

    return [sbox[x] for x in estado]


def sustituir_bytes_inverso(estado: List[int]) -> List[int]:
    # Realiza la sustitución inversa a la anterior

    return [inv_sbox[x] for x in estado]


def desplazar_filas(estado: List[int]) -> List[int]:
    # Realiza el desplazamiento de filas

    return [
        estado[0], estado[5], estado[10], estado[15],
        estado[4], estado[9], estado[14], estado[3],
        estado[8], estado[13], estado[2], estado[7],
        estado[12], estado[1], estado[6], estado[11]
    ]


def desplazar_filas_inverso(estado: List[int]) -> List[int]:
    # Realiza lo contrario a la función anterior
    # La primera fila no se mueve, la segunda se desplaza 1 posición, la tercera 2 y la cuarta 3.

    return [
        estado[0], estado[13], estado[10], estado[7],
        estado[4], estado[1], estado[14], estado[11],
        estado[8], estado[5], estado[2], estado[15],
        estado[12], estado[9], estado[6], estado[3]
    ]


def multiplicacion_galois(a: int, b: int) -> int:
    # Realiza la multiplicación en el campo de Galois.

    p = 0

    for _ in range(8):
        if b & 1:
            p ^= a
        bit_alto = a & 0x80
        a <<= 1
        if bit_alto:
            a ^= 0x1B  # Polinomio irreducible para AES
        b >>= 1

    return p & 0xFF



# Precalculamos las multiplicaciones por 2 y 3 para optimizar
mul2: List[int] = [multiplicacion_galois(i, 2) for i in range(256)]
mul3: List[int] = [multiplicacion_galois(i, 3) for i in range(256)]

def mezclar_columnas(estado: List[int]) -> List[int]:
    # Realiza el paso de mezclar las columnas
    # Cada columna se trata como un polinomio sobre GF(2^8) y se multiplica por un polinomio fijo c(x) = 3x^3 + x^2 + x + 2

    nuevo_estado = []

    for i in range(4):
        col = estado[i*4:(i+1)*4]
        nuevo_estado.extend([
            mul2[col[0]] ^ mul3[col[1]] ^ col[2] ^ col[3],
            col[0] ^ mul2[col[1]] ^ mul3[col[2]] ^ col[3],
            col[0] ^ col[1] ^ mul2[col[2]] ^ mul3[col[3]],
            mul3[col[0]] ^ col[1] ^ col[2] ^ mul2[col[3]]
        ])

    return nuevo_estado


def mezclar_columnas_inverso(estado: List[int]) -> List[int]:
    # Realiza lo contrario a la función anterior

    nuevo_estado = []

    for i in range(4):
        columna = estado[i*4:(i+1)*4]
        nueva_columna = [
            multiplicacion_galois(columna[0], 14) ^ multiplicacion_galois(columna[1], 11) ^
            multiplicacion_galois(columna[2], 13) ^ multiplicacion_galois(columna[3], 9),
            multiplicacion_galois(columna[0], 9) ^ multiplicacion_galois(columna[1], 14) ^
            multiplicacion_galois(columna[2], 11) ^ multiplicacion_galois(columna[3], 13),
            multiplicacion_galois(columna[0], 13) ^ multiplicacion_galois(columna[1], 9) ^
            multiplicacion_galois(columna[2], 14) ^ multiplicacion_galois(columna[3], 11),
            multiplicacion_galois(columna[0], 11) ^ multiplicacion_galois(columna[1], 13) ^
            multiplicacion_galois(columna[2], 9) ^ multiplicacion_galois(columna[3], 14)
        ]
        nuevo_estado.extend(nueva_columna)

    return nuevo_estado


def agregar_clave_ronda(estado: List[int], clave_ronda: List[int]) -> List[int]:
    
    # Realiza la adición de la clave de ronda al estado.
    
    return [s ^ k for s, k in zip(estado, clave_ronda)]


def expandir_clave(clave: List[int]) -> List[int]:
    # Realiza la expansión de la clave para generar las claves de las rondas.
    
    clave_expandida = list(clave)

    for i in range(4, 4 * 11):  # 11 claves de ronda para AES-128
        palabra = clave_expandida[(i-1)*4:i*4]
        if i % 4 == 0:
            palabra = sustituir_bytes(palabra[1:] + palabra[:1])  # Rotar y aplicar SubBytes
            palabra[0] ^= rcon[i//4]
        nueva_palabra = [clave_expandida[(i-4)*4 + j] ^ palabra[j] for j in range(4)]
        clave_expandida.extend(nueva_palabra)
        
    return clave_expandida


def padding(datos: bytes) -> bytes:
    # Aplica relleno PKCS7 a los datos de entrada.

    tamaño_bloque = 16
    longitud_relleno = tamaño_bloque - (len(datos) % tamaño_bloque)

    if longitud_relleno == 0:
        longitud_relleno = tamaño_bloque
    relleno = bytes([longitud_relleno] * longitud_relleno)

    return datos + relleno

def quitar_padding(datos_rellenados: bytes) -> bytes:
    #Elimina el relleno 

    longitud_relleno = datos_rellenados[-1]

    if longitud_relleno > 16 or longitud_relleno == 0:
        return datos_rellenados  
    
    for i in range(1, longitud_relleno + 1):
        if datos_rellenados[-i] != longitud_relleno:
            return datos_rellenados  
        
    return datos_rellenados[:-longitud_relleno]
