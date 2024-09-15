import time
import secrets
from src.aes.aes_ctr import cifrar_ctr, descifrar_ctr
from src.utils.sts_tests import ejecutar_pruebas_sts

def ejecutar_vectores_prueba():

    print("\n----- Vectores de prueba AES-CTR -----")
    vectores_prueba = [
        {
            "texto_plano": "6bc1bee22e409f96e93d7e117393172a",
            "clave": "2b7e151628aed2a6abf7158809cf4f3c",
            "nonce": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "texto_cifrado_esperado": "874d6191b620e3261bef6864990db6ce"
        },
        {
            "texto_plano": "ae2d8a571e03ac9c9eb76fac45af8e51",
            "clave": "2b7e151628aed2a6abf7158809cf4f3c",
            "nonce": "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
            "texto_cifrado_esperado": "9806f66b7970fdff8617187bb9fffdff"
        },
    ]

    for i, vector in enumerate(vectores_prueba, 1):
        print(f"\nVector de prueba {i}:")
        texto_plano = bytes.fromhex(vector["texto_plano"])
        clave = bytes.fromhex(vector["clave"])
        nonce = bytes.fromhex(vector["nonce"])
        texto_cifrado_esperado = vector["texto_cifrado_esperado"]
        texto_cifrado = cifrar_ctr(texto_plano, clave, nonce)
        texto_descifrado = descifrar_ctr(texto_cifrado, clave, nonce)

        print(f"Texto plano:           {texto_plano.hex()}")
        print(f"Clave:                 {clave.hex()}")
        print(f"Nonce:                 {nonce.hex()}")
        print(f"Texto cifrado esperado: {texto_cifrado_esperado}")
        print(f"Texto cifrado real:    {texto_cifrado.hex()}")
        print(f"Texto descifrado:      {texto_descifrado.hex()}")
        assert texto_cifrado.hex() == texto_cifrado_esperado.lower(), "Fallo en el cifrado"
        assert texto_descifrado.hex() == texto_plano.hex(), "Fallo en el descifrado"

        print("Prueba superada con éxito")


def probar_tiempo_ejecucion():

    print("\n----- Prueba de tiempo de ejecución AES-CTR -----")
    clave = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    tamaños = [16, 128, 1024]  # Probar con 16 B, 128 B, 1 KB
    iteraciones = 500

    for tamaño in tamaños:
        tiempo_total_cifrado = 0
        tiempo_total_descifrado = 0

        for _ in range(iteraciones):
            texto_plano = secrets.token_bytes(tamaño)
            inicio = time.time()
            texto_cifrado = cifrar_ctr(texto_plano, clave, nonce)
            tiempo_cifrado = time.time() - inicio
            inicio = time.time()
            texto_descifrado = descifrar_ctr(texto_cifrado, clave, nonce)
            tiempo_descifrado = time.time() - inicio
            tiempo_total_cifrado += tiempo_cifrado
            tiempo_total_descifrado += tiempo_descifrado
            assert texto_descifrado == texto_plano, "Fallo en el descifrado"

        tiempo_promedio_cifrado = tiempo_total_cifrado / iteraciones
        tiempo_promedio_descifrado = tiempo_total_descifrado / iteraciones

        print(f"Tamaño de entrada: {tamaño} bytes")
        print(f"Tiempo promedio de cifrado: {tiempo_promedio_cifrado:.6f} segundos")
        print(f"Tiempo promedio de descifrado: {tiempo_promedio_descifrado:.6f} segundos")
        print("--------------------")


def probar_sensibilidad_clave():

    print("\n----- Prueba de sensibilidad a la clave AES-CTR -----")
    clave1 = secrets.token_bytes(16)
    clave2 = bytearray(clave1)
    clave2[0] ^= 1  # Cambiar un bit en la clave
    nonce = secrets.token_bytes(8)
    texto_plano = b'Este es un mensaje de prueba para sensibilidad a la clave'
    texto_cifrado1 = cifrar_ctr(texto_plano, clave1, nonce)
    texto_cifrado2 = cifrar_ctr(texto_plano, bytes(clave2), nonce)
    
    diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))
    print(f"Bits diferentes en el texto cifrado: {diferencia_bits} de {len(texto_cifrado1) * 8}")
    print(f"Porcentaje de diferencia: {(diferencia_bits / (len(texto_cifrado1) * 8)) * 100:.2f}%")


def probar_seguridad_nonce():

    print("\n----- Prueba de seguridad del nonce AES-CTR -----")
    clave = secrets.token_bytes(16)
    nonce1 = secrets.token_bytes(8)
    nonce2 = secrets.token_bytes(8)
    texto_plano = b'Este es un mensaje de prueba para seguridad del nonce'
    texto_cifrado1 = cifrar_ctr(texto_plano, clave, nonce1)
    texto_cifrado2 = cifrar_ctr(texto_plano, clave, nonce2)
    
    print(f"Texto cifrado 1: {texto_cifrado1.hex()}")
    print(f"Texto cifrado 2: {texto_cifrado2.hex()}")
    print(f"Los textos cifrados son {'diferentes' if texto_cifrado1 != texto_cifrado2 else 'iguales'}")


def probar_sts():
    print("\n----- Prueba estadística AES-CTR -----")
    clave = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    texto_plano = secrets.token_bytes(1000000)  # 1 MB de datos aleatorios
    texto_cifrado = cifrar_ctr(texto_plano, clave, nonce)
    resultados = ejecutar_pruebas_sts(texto_cifrado)
    
    for nombre_prueba, p_valor in resultados.items():
        print(f"{nombre_prueba}: p-valor = {p_valor}")
        print("PASA" if p_valor > 0.01 else "FALLA")


def probar_patron_visual():
    print("\n----- Prueba de patrón visual AES-CTR -----")
    clave = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    texto_plano = b'A' * 64 + b'B' * 64 + b'C' * 64 + b'D' * 64
    texto_cifrado = cifrar_ctr(texto_plano, clave, nonce)

    print("Patrón del texto plano:")
    imprimir_patron_bloques(texto_plano)
    print("\nPatrón del texto cifrado:")
    imprimir_patron_bloques(texto_cifrado)


def imprimir_patron_bloques(datos):

    for i in range(0, len(datos), 16):
        bloque = datos[i:i+16]
        print(''.join([chr(ord('A') + j % 26) for j in range(16)]), end=' ')
    print()

    for i in range(0, len(datos), 16):
        bloque = datos[i:i+16]
        print(''.join([chr(ord('A') + hash(bytes(bloque)) % 26) for _ in range(16)]), end=' ')
    print()


def probar_difusion():

    print("\n----- Prueba de difusión AES-CTR -----")
    clave = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    texto_plano = b'A' * 32
    texto_cifrado1 = cifrar_ctr(texto_plano, clave, nonce)
    cambios_bits = []

    for i in range(256): 
        texto_plano_modificado = bytearray(texto_plano)
        byte_index = i // 8
        bit_index = i % 8
        texto_plano_modificado[byte_index] ^= (1 << bit_index)
        texto_cifrado2 = cifrar_ctr(bytes(texto_plano_modificado), clave, nonce)
        diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))
        cambios_bits.append(diferencia_bits)
    
    promedio_cambios = sum(cambios_bits) / len(cambios_bits)
    print(f"Promedio de cambios de bits: {promedio_cambios:.2f} de {len(texto_cifrado1) * 8} bits")
    print(f"Porcentaje de cambio: {(promedio_cambios / (len(texto_cifrado1) * 8)) * 100:.2f}%")


def probar_desbordamiento_contador():

    print("\n----- Prueba de desbordamiento del contador AES-CTR -----")
    clave = secrets.token_bytes(16)
    nonce = b'\xff' * 8  # Comenzar con el valor máximo del nonce
    texto_plano = b'Prueba de desbordamiento del contador' * 1000  # Texto plano grande para forzar el desbordamiento
    texto_cifrado = cifrar_ctr(texto_plano, clave, nonce)
    texto_descifrado = descifrar_ctr(texto_cifrado, clave, nonce)

    print(f"Longitud del texto plano: {len(texto_plano)} bytes")
    print(f"Longitud del texto cifrado: {len(texto_cifrado)} bytes")
    print(f"Longitud del texto descifrado: {len(texto_descifrado)} bytes")
    assert texto_descifrado == texto_plano, "La prueba de desbordamiento del contador falló"
    print("Prueba de desbordamiento del contador superada con éxito")


def ejecutar_todas_las_pruebas():
    ejecutar_vectores_prueba()
    probar_tiempo_ejecucion()
    probar_patron_visual()
    probar_difusion()
    probar_desbordamiento_contador()
    probar_sensibilidad_clave()
    probar_seguridad_nonce()
    probar_sts()


if __name__ == "__main__":
    ejecutar_todas_las_pruebas()