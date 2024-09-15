import time
import secrets
from src.aes.aes_ecb import cifrar_ecb, descifrar_ecb
from src.utils.sts_tests import ejecutar_pruebas_sts

def ejecutar_vectores_prueba():

    print("\n----- Vectores de prueba AES-ECB -----")
    vectores_prueba = [
        {
            "texto_plano": "00112233445566778899aabbccddeeff",
            "clave": "000102030405060708090a0b0c0d0e0f",
            "texto_cifrado_esperado": "69c4e0d86a7b0430d8cdb78070b4c55a"
        },
        {
            "texto_plano": "3243f6a8885a308d313198a2e0370734",
            "clave": "2b7e151628aed2a6abf7158809cf4f3c",
            "texto_cifrado_esperado": "3925841d02dc09fbdc118597196a0b32"
        },
        {
            "texto_plano": "6bc1bee22e409f96e93d7e117393172a",
            "clave": "2b7e151628aed2a6abf7158809cf4f3c",
            "texto_cifrado_esperado": "3ad77bb40d7a3660a89ecaf32466ef97"
        },
        {
            "texto_plano": "ae2d8a571e03ac9c9eb76fac45af8e51",
            "clave": "2b7e151628aed2a6abf7158809cf4f3c",
            "texto_cifrado_esperado": "f5d3d58503b9699de785895a96fdbaaf"
        }
      
    ]

    for i, vector in enumerate(vectores_prueba, 1):
        print(f"\nVector de prueba {i}:")
        texto_plano = bytes.fromhex(vector["texto_plano"])
        clave = bytes.fromhex(vector["clave"])
        texto_cifrado_esperado = vector["texto_cifrado_esperado"]
        texto_cifrado = cifrar_ecb(texto_plano, clave)
        texto_descifrado = descifrar_ecb(texto_cifrado, clave)

        print(f"Texto plano:           {texto_plano.hex()}")
        print(f"Clave:                 {clave.hex()}")
        print(f"Texto cifrado esperado: {texto_cifrado_esperado}")
        print(f"Texto cifrado real:    {texto_cifrado[:16].hex()}")
        print(f"Texto descifrado:      {texto_descifrado[:16].hex()}")
        assert texto_cifrado[:16].hex() == texto_cifrado_esperado.lower(), "Fallo en el cifrado"
        assert texto_descifrado[:16].hex() == texto_plano.hex(), "Fallo en el descifrado"
        print("Prueba superada con éxito")


def probar_diferentes_tamaños():

    print("\n----- Prueba de diferentes tamaños de texto plano -----")
    clave = secrets.token_bytes(16)
    tamaños = [15, 16, 17, 31, 32, 33, 63, 64, 65]

    for tamaño in tamaños:
        texto_plano = secrets.token_bytes(tamaño)
        texto_cifrado = cifrar_ecb(texto_plano, clave)
        texto_descifrado = descifrar_ecb(texto_cifrado, clave)

        print(f"\nTamaño del texto plano: {tamaño} bytes")
        print(f"Tamaño del texto cifrado: {len(texto_cifrado)} bytes")
        print(f"Tamaño del texto descifrado: {len(texto_descifrado)} bytes")
        assert texto_descifrado == texto_plano, f"Fallo en cifrado/descifrado para tamaño {tamaño}"
        print(f"Prueba superada para tamaño {tamaño}")


def imprimir_patron_bloques(datos):

    for i in range(0, len(datos), 16):
        bloque = datos[i:i+16]
        print(''.join([chr(ord('A') + j % 26) for j in range(16)]), end=' ')

    print()

    for i in range(0, len(datos), 16):
        bloque = datos[i:i+16]
        print(''.join([chr(ord('A') + hash(bytes(bloque)) % 26) for _ in range(16)]), end=' ')

    print()

def probar_patron_visual():

    print("\n----- Prueba de patrón visual AES-ECB -----")
    clave = secrets.token_bytes(16)
    texto_plano = b'A' * 64 + b'B' * 64 + b'C' * 64 + b'D' * 64
    texto_cifrado = cifrar_ecb(texto_plano, clave)

    print("Patrón del texto plano:")
    imprimir_patron_bloques(texto_plano)
    print("\nPatrón del texto cifrado:")
    imprimir_patron_bloques(texto_cifrado)



def probar_tiempo_ejecucion():

    print("\n----- Prueba de tiempo de ejecución AES-ECB -----")
    clave = secrets.token_bytes(16)
    tamaños = [16, 128, 1024]  # 16 B, 128 B, 1 KB
    iteraciones = 500

    for tamaño in tamaños:
        tiempo_total_cifrado = 0
        tiempo_total_descifrado = 0

        for _ in range(iteraciones):
            texto_plano = secrets.token_bytes(tamaño)

            inicio = time.time()
            texto_cifrado = cifrar_ecb(texto_plano, clave)
            tiempo_cifrado = time.time() - inicio

            inicio = time.time()
            texto_descifrado = descifrar_ecb(texto_cifrado, clave)
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


def probar_difusion():

    print("\n----- Prueba de difusión AES-ECB -----")
    clave = secrets.token_bytes(16)
    texto_plano = b'A' * 16
    texto_cifrado1 = cifrar_ecb(texto_plano, clave)
    cambios_bits = []

    for i in range(128):
        texto_plano_modificado = bytearray(texto_plano)
        byte_index = i // 8
        bit_index = i % 8
        texto_plano_modificado[byte_index] ^= (1 << bit_index)
        texto_cifrado2 = cifrar_ecb(bytes(texto_plano_modificado), clave)
        diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))
        cambios_bits.append(diferencia_bits)
    
    promedio_cambios = sum(cambios_bits) / len(cambios_bits)
    print(f"Promedio de cambios de bits: {promedio_cambios:.2f} de 128 bits")
    print(f"Porcentaje de cambio: {(promedio_cambios / 128) * 100:.2f}%")


def probar_sensibilidad_clave():

    print("\n----- Prueba de sensibilidad a la clave AES-ECB -----")
    clave1 = secrets.token_bytes(16)
    clave2 = bytearray(clave1)
    clave2[0] ^= 1  # Cambiar un bit en la clave
    texto_plano = b'Este es un mensaje de prueba para sensibilidad a la clave'
    texto_cifrado1 = cifrar_ecb(texto_plano, clave1)
    texto_cifrado2 = cifrar_ecb(texto_plano, bytes(clave2))
    diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))

    print(f"Bits diferentes en el texto cifrado: {diferencia_bits} de {len(texto_cifrado1) * 8}")
    print(f"Porcentaje de diferencia: {(diferencia_bits / (len(texto_cifrado1) * 8)) * 100:.2f}%")


def probar_sts():

    print("\n----- Pruebas estadística AES-ECB -----")
    clave = secrets.token_bytes(16)
    texto_plano = secrets.token_bytes(1000000) 
    texto_cifrado = cifrar_ecb(texto_plano, clave)
    resultados = ejecutar_pruebas_sts(texto_cifrado)
    
    for nombre_prueba, p_valor in resultados.items():
        print(f"{nombre_prueba}: p-valor = {p_valor}")
        print("PASA" if p_valor > 0.01 else "FALLA")


def ejecutar_todas_las_pruebas():
    ejecutar_vectores_prueba()
    probar_diferentes_tamaños()
    probar_tiempo_ejecucion()
    probar_patron_visual()
    probar_difusion()
    probar_sensibilidad_clave()
    probar_sts()

if __name__ == "__main__":
    ejecutar_todas_las_pruebas()

