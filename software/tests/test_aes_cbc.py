import time
import secrets
from src.aes.aes_cbc import cifrar_cbc, descifrar_cbc
from src.utils.sts_tests import ejecutar_pruebas_sts

def ejecutar_vectores_prueba():

    print("\n----- Vectores de prueba AES-CBC -----")
    vectores_prueba = [
        {
            "texto_plano": "6bc1bee22e409f96e93d7e117393172a",
            "clave": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "texto_cifrado_esperado": "7649abac8119b246cee98e9b12e9197d"
        },
         {
            "texto_plano": "00000000000000000000000000000000",
            "clave": "10a58869d74be5a374cf867cfb473859",
            "iv": "00000000000000000000000000000000",
            "texto_cifrado_esperado": "6d251e6944b051e04eaa6fb4dbf78465"
        },
    ]

    for i, vector in enumerate(vectores_prueba, 1):
        print(f"\nVector de prueba {i}:")
        texto_plano = bytes.fromhex(vector["texto_plano"])
        clave = bytes.fromhex(vector["clave"])
        iv = bytes.fromhex(vector["iv"])
        texto_cifrado_esperado = vector["texto_cifrado_esperado"]
        texto_cifrado = cifrar_cbc(texto_plano, clave, iv)
        texto_descifrado = descifrar_cbc(texto_cifrado, clave, iv)

        print(f"Texto plano:           {texto_plano.hex()}")
        print(f"Clave:                 {clave.hex()}")
        print(f"IV:                    {iv.hex()}")
        print(f"Texto cifrado esperado: {texto_cifrado_esperado}")
        print(f"Texto descifrado:      {texto_descifrado.hex()}")
        assert texto_cifrado[:16].hex() == texto_cifrado_esperado.lower(), "Fallo en el cifrado"
        assert texto_descifrado == texto_plano, "Fallo en el descifrado"

        print("Prueba superada con éxito")


def probar_tiempo_ejecucion():

    print("\n----- Prueba de tiempo de ejecución AES-CBC -----")
    clave = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    tamaños = [16, 128, 1024]  # Probar con 16 B, 128 B, 1 KB
    iteraciones = 500

    for tamaño in tamaños:
        tiempo_total_cifrado = 0
        tiempo_total_descifrado = 0

        for _ in range(iteraciones):
            texto_plano = secrets.token_bytes(tamaño)
            inicio = time.time()
            texto_cifrado = cifrar_cbc(texto_plano, clave, iv)
            tiempo_cifrado = time.time() - inicio
            inicio = time.time()
            texto_descifrado = descifrar_cbc(texto_cifrado, clave, iv)
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

    print("\n----- Prueba de difusión AES-CBC -----")
    clave = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    texto_plano = b'A' * 32
    texto_cifrado1 = cifrar_cbc(texto_plano, clave, iv)
    cambios_bits = []

    for i in range(256): 
        texto_plano_modificado = bytearray(texto_plano)
        byte_index = i // 8
        bit_index = i % 8
        texto_plano_modificado[byte_index] ^= (1 << bit_index)
        texto_cifrado2 = cifrar_cbc(bytes(texto_plano_modificado), clave, iv)
        diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))
        cambios_bits.append(diferencia_bits)
    
    promedio_cambios = sum(cambios_bits) / len(cambios_bits)
    print(f"Promedio de cambios de bits: {promedio_cambios:.2f} de {len(texto_cifrado1) * 8} bits")
    print(f"Porcentaje de cambio: {(promedio_cambios / (len(texto_cifrado1) * 8)) * 100:.2f}%")


def probar_sensibilidad_clave():

    print("\n----- Prueba de sensibilidad a la clave AES-CBC -----")
    clave1 = secrets.token_bytes(16)
    clave2 = bytearray(clave1)
    clave2[0] ^= 1  # Cambiar un bit en la clave
    iv = secrets.token_bytes(16)
    texto_plano = b'Este es un mensaje de prueba para sensibilidad a la clave'
    texto_cifrado1 = cifrar_cbc(texto_plano, clave1, iv)
    texto_cifrado2 = cifrar_cbc(texto_plano, bytes(clave2), iv)
    diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))

    print(f"Bits diferentes en el texto cifrado: {diferencia_bits} de {len(texto_cifrado1) * 8}")
    print(f"Porcentaje de diferencia: {(diferencia_bits / (len(texto_cifrado1) * 8)) * 100:.2f}%")


def probar_seguridad_iv():

    print("\n----- Prueba de seguridad del IV AES-CBC -----")
    clave = secrets.token_bytes(16)
    iv1 = secrets.token_bytes(16)
    iv2 = secrets.token_bytes(16)
    texto_plano = b'Este es un mensaje de prueba para seguridad del IV'
    texto_cifrado1 = cifrar_cbc(texto_plano, clave, iv1)
    texto_cifrado2 = cifrar_cbc(texto_plano, clave, iv2)
    
    print(f"Texto cifrado 1: {texto_cifrado1.hex()}")
    print(f"Texto cifrado 2: {texto_cifrado2.hex()}")
    print(f"Los textos cifrados son {'diferentes' if texto_cifrado1 != texto_cifrado2 else 'iguales'}")


def probar_sts():

    print("\n----- Prueba estadística AES-CBC -----")
    clave = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    texto_plano = secrets.token_bytes(1000000)  
    texto_cifrado = cifrar_cbc(texto_plano, clave, iv)
    resultados = ejecutar_pruebas_sts(texto_cifrado)
    
    for nombre_prueba, p_valor in resultados.items():
        print(f"{nombre_prueba}: p-valor = {p_valor}")
        print("PASA" if p_valor > 0.01 else "FALLA")


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

    print("\n----- Prueba de patrón visual AES-CBC -----")
    clave = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    texto_plano = b'A' * 64 + b'B' * 64 + b'C' * 64 + b'D' * 64
    texto_cifrado = cifrar_cbc(texto_plano, clave, iv)

    print("Patrón del texto plano:")
    imprimir_patron_bloques(texto_plano)
    print("\nPatrón del texto cifrado:")
    imprimir_patron_bloques(texto_cifrado)


def probar_propagacion_errores():

    print("\n----- Prueba de propagación de errores AES-CBC -----")
    clave = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    texto_plano = b'Este es un mensaje de prueba para propagacion de errores en modo CBC.' * 2
    texto_cifrado = cifrar_cbc(texto_plano, clave, iv)
    
    # Introducir un error en el segundo bloque del texto cifrado
    texto_cifrado_corrupto = bytearray(texto_cifrado)
    texto_cifrado_corrupto[17] ^= 1
    texto_descifrado = descifrar_cbc(bytes(texto_cifrado_corrupto), clave, iv)
    
    print("Texto plano original:")
    print(texto_plano)
    print("\nTexto descifrado con error:")
    print(texto_descifrado)
    print("\nDiferencias:")
    for i, (original, descifrado) in enumerate(zip(texto_plano, texto_descifrado)):
        if original != descifrado:
            print(f"Byte {i}: {original} -> {descifrado}")


def ejecutar_todas_las_pruebas():
    ejecutar_vectores_prueba()
    probar_tiempo_ejecucion()
    probar_patron_visual()
    probar_propagacion_errores()
    probar_difusion()
    probar_sensibilidad_clave()
    probar_seguridad_iv()
    probar_sts()

if __name__ == "__main__":
    ejecutar_todas_las_pruebas()