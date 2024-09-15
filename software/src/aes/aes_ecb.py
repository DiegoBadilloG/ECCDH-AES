# Este módulo proporciona funciones para cifrar y descifrar datos utilizando AES-128 en modo ECB (Electronic Codebook). 

from typing import Union, List
from .aes_common import (
    sustituir_bytes, sustituir_bytes_inverso, desplazar_filas, desplazar_filas_inverso, 
    multiplicacion_galois, mezclar_columnas, mezclar_columnas_inverso, agregar_clave_ronda, 
    expandir_clave, padding, quitar_padding
)

def cifrar_ecb(texto_plano: Union[str, List[int], bytes], clave: Union[str, List[int], bytes]) -> bytes:

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
    
    for i in range(0, len(texto_plano), 16):
        bloque = bytearray(texto_plano[i:i+16])
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
    
    return bytes(texto_cifrado)


def descifrar_ecb(texto_cifrado: Union[str, List[int], bytes], clave: Union[str, List[int], bytes]) -> bytes:

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

    for i in range(0, len(texto_cifrado), 16):
        bloque = bytearray(texto_cifrado[i:i+16])
        bloque = agregar_clave_ronda(bloque, clave_expandida[-16:])
        
        for ronda in range(9, 0, -1):
            bloque = desplazar_filas_inverso(bloque)
            bloque = sustituir_bytes_inverso(bloque)
            bloque = agregar_clave_ronda(bloque, clave_expandida[ronda*16:(ronda+1)*16])
            bloque = mezclar_columnas_inverso(bloque)
        
        bloque = desplazar_filas_inverso(bloque)
        bloque = sustituir_bytes_inverso(bloque)
        bloque = agregar_clave_ronda(bloque, clave_expandida[:16])
        
        texto_plano_rellenado.extend(bloque)
    
    return quitar_padding(bytes(texto_plano_rellenado))