# Este módulo proporciona funciones para cifrar y descifrar datos utilizando AES-128 en modo CBC (). 

from typing import Union, List
from .aes_common import (
    sustituir_bytes, sustituir_bytes_inverso, desplazar_filas, desplazar_filas_inverso,
    multiplicacion_galois, mezclar_columnas, mezclar_columnas_inverso, agregar_clave_ronda,
    expandir_clave, padding, quitar_padding
)

def cifrar_cbc(texto_plano: Union[str, List[int], bytes], clave: Union[str, List[int], bytes], vector_inicial: bytes) -> bytes:

    if len(clave) != 16:
        raise ValueError("La clave debe tener 16 bytes de longitud")
    
    if isinstance(texto_plano, str):
        texto_plano = texto_plano.encode()
    elif isinstance(texto_plano, list):
        texto_plano = bytes(texto_plano)

    if not isinstance(texto_plano, bytes):
        raise TypeError("El texto plano debe ser bytes, una lista de enteros o una cadena")
    
    texto_plano = padding(texto_plano)
    clave_expandida = expandir_clave(list(clave))
    texto_cifrado = bytearray()
    bloque_previo = vector_inicial

    for i in range(0, len(texto_plano), 16):
        bloque = bytearray(texto_plano[i:i+16])
        bloque = bytes([b ^ p for b, p in zip(bloque, bloque_previo)])
        bloque = agregar_clave_ronda(bloque, clave_expandida[:16])
        
        for ronda in range(1, 10):
            bloque = sustituir_bytes(bloque)
            bloque = desplazar_filas(bloque)
            bloque = mezclar_columnas(bloque)
            bloque = agregar_clave_ronda(bloque, clave_expandida[ronda*16:(ronda+1)*16])
        
        bloque = sustituir_bytes(bloque)
        bloque = desplazar_filas(bloque)
        bloque = agregar_clave_ronda(bloque, clave_expandida[-16:])

        texto_cifrado.extend(bloque)
        bloque_previo = bloque
    
    return bytes(texto_cifrado)


def descifrar_cbc(texto_cifrado: Union[str, List[int], bytes], clave: Union[str, List[int], bytes], vector_inicial: bytes) -> bytes:
    
    if len(clave) != 16:
        raise ValueError("La clave debe tener 16 bytes de longitud")
    
    if isinstance(texto_cifrado, str):
        try:
            texto_cifrado = bytes.fromhex(texto_cifrado)
        except ValueError:
            raise ValueError("Texto cifrado inválido: debe ser una cadena hexadecimal si es string")
    elif isinstance(texto_cifrado, list):
        texto_cifrado = bytes(texto_cifrado)

    if not isinstance(texto_cifrado, bytes):
        raise TypeError("El texto cifrado debe ser bytes, una lista de enteros o una cadena hexadecimal")

    if len(texto_cifrado) % 16 != 0:
        raise ValueError("La longitud del texto cifrado debe ser múltiplo de 16 bytes")

    clave_expandida = expandir_clave(list(clave))
    texto_plano_rellenado = bytearray()
    bloque_previo = vector_inicial

    for i in range(0, len(texto_cifrado), 16):
        bloque = bytearray(texto_cifrado[i:i+16])
        bloque_descifrado = bloque.copy()
        bloque_descifrado = agregar_clave_ronda(bloque_descifrado, clave_expandida[-16:])
        
        for ronda in range(9, 0, -1):
            bloque_descifrado = desplazar_filas_inverso(bloque_descifrado)
            bloque_descifrado = sustituir_bytes_inverso(bloque_descifrado)
            bloque_descifrado = agregar_clave_ronda(bloque_descifrado, clave_expandida[ronda*16:(ronda+1)*16])
            bloque_descifrado = mezclar_columnas_inverso(bloque_descifrado)
        
        bloque_descifrado = desplazar_filas_inverso(bloque_descifrado)
        bloque_descifrado = sustituir_bytes_inverso(bloque_descifrado)
        bloque_descifrado = agregar_clave_ronda(bloque_descifrado, clave_expandida[:16])
        bloque_descifrado = bytes([d ^ p for d, p in zip(bloque_descifrado, bloque_previo)])
        texto_plano_rellenado.extend(bloque_descifrado)
        bloque_previo = bloque
    
    return quitar_padding(bytes(texto_plano_rellenado))