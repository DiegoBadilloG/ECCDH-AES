# Este módulo proporciona funciones para cifrar y descifrar datos utilizando AES-128 en modo CTR (). 

from typing import Union, List
from .aes_common import (
    sustituir_bytes, desplazar_filas, mezclar_columnas, agregar_clave_ronda,
    expandir_clave
)


def incrementar_contador(contador: bytearray) -> bytearray:
    # Incrementa el contador para el modo CTR

    for i in range(15, -1, -1):
        contador[i] = (contador[i] + 1) & 0xFF
        if contador[i] != 0:
            break

    return contador


def cifrar_ctr(texto_plano: Union[str, List[int], bytes], clave: Union[str, List[int], bytes], nonce: bytes) -> bytes:
    if len(clave) != 16:
        raise ValueError("La clave debe tener 16 bytes de longitud")
    
    if isinstance(texto_plano, str):
        texto_plano = texto_plano.encode()
    elif isinstance(texto_plano, list):
        texto_plano = bytes(texto_plano)

    if not isinstance(texto_plano, bytes):
        raise TypeError("El texto plano debe ser bytes, una lista de enteros o una cadena")
    
    # No usamos padding porque es un cifrado en flujo
    clave_expandida = expandir_clave(list(clave))
    texto_cifrado = bytearray()
    contador = bytearray(16)  
    
    for i in range(0, len(texto_plano), 16):
        bloque = nonce + contador[8:]  # Usamos los últimos 8 bytes del contador
        bloque = agregar_clave_ronda(bloque, clave_expandida[:16])
        
        for ronda in range(1, 10):
            bloque = sustituir_bytes(bloque)
            bloque = desplazar_filas(bloque)
            bloque = mezclar_columnas(bloque)
            bloque = agregar_clave_ronda(bloque, clave_expandida[ronda*16:(ronda+1)*16])
        
        bloque = sustituir_bytes(bloque)
        bloque = desplazar_filas(bloque)
        bloque = agregar_clave_ronda(bloque, clave_expandida[-16:])
        
        for j in range(min(16, len(texto_plano) - i)):
            texto_cifrado.append(texto_plano[i + j] ^ bloque[j])
        
        contador = incrementar_contador(contador)
    
    return bytes(texto_cifrado)

def descifrar_ctr(texto_cifrado: Union[str, List[int], bytes], clave: Union[str, List[int], bytes], nonce: bytes) -> bytes:
    # Se hace de la misma forma que el cifrado
    return cifrar_ctr(texto_cifrado, clave, nonce)