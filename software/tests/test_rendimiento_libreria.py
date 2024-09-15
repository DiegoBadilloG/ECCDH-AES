''' Evalúa el rendimiento y la eficiencia de las implementaciones de AES con la librería Crypto,
 proporcionando métricas comparativas entre los diferentes modos para poder compararlo con nuestra implementación '''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time
import secrets

def cifrar_descifrar_aes(modo, datos, clave):

    if modo == AES.MODE_ECB:
        cifrador = AES.new(clave, modo)
        datos_rellenados = pad(datos, AES.block_size)
        datos_cifrados = cifrador.encrypt(datos_rellenados)
        datos_descifrados = unpad(cifrador.decrypt(datos_cifrados), AES.block_size)
    elif modo == AES.MODE_CBC:
        iv = get_random_bytes(AES.block_size)
        cifrador = AES.new(clave, modo, iv)
        datos_rellenados = pad(datos, AES.block_size)
        datos_cifrados = cifrador.encrypt(datos_rellenados)
        cifrador = AES.new(clave, modo, iv)
        datos_descifrados = unpad(cifrador.decrypt(datos_cifrados), AES.block_size)
    elif modo == AES.MODE_CTR:
        nonce = get_random_bytes(8)
        cifrador = AES.new(clave, modo, nonce=nonce)
        datos_cifrados = cifrador.encrypt(datos)
        cifrador = AES.new(clave, modo, nonce=nonce)
        datos_descifrados = cifrador.decrypt(datos_cifrados)

    else:
        raise ValueError("Modo no soportado")
    
    return datos_cifrados, datos_descifrados


def probar_rendimiento(modo, datos, clave, iteraciones=500):

    tiempo_total_cifrado = 0
    tiempo_total_descifrado = 0

    for _ in range(iteraciones):
        tiempo_inicio = time.time()
        datos_cifrados, _ = cifrar_descifrar_aes(modo, datos, clave)
        tiempo_total_cifrado += (time.time() - tiempo_inicio) * 1000

        tiempo_inicio = time.time()
        cifrar_descifrar_aes(modo, datos_cifrados, clave)
        tiempo_total_descifrado += (time.time() - tiempo_inicio) * 1000

    tiempo_promedio_cifrado = tiempo_total_cifrado / iteraciones
    tiempo_promedio_descifrado = tiempo_total_descifrado / iteraciones

    return tiempo_promedio_cifrado, tiempo_promedio_descifrado


def probar_difusion(modo, clave):

    texto_plano = b'A' * 16
    
    if modo == AES.MODE_CTR:
        nonce = get_random_bytes(8)
        cifrador = AES.new(clave, modo, nonce=nonce)
    elif modo == AES.MODE_CBC:
        iv = get_random_bytes(AES.block_size)
        cifrador = AES.new(clave, modo, iv)
    else: 
        cifrador = AES.new(clave, modo)
    
    texto_cifrado1 = cifrador.encrypt(texto_plano if modo == AES.MODE_CTR else pad(texto_plano, AES.block_size))
    cambios_bits = []

    for i in range(128):
        texto_plano_modificado = bytearray(texto_plano)
        indice_byte = i // 8
        indice_bit = i % 8
        texto_plano_modificado[indice_byte] ^= (1 << indice_bit)
        
        if modo == AES.MODE_CTR:
            cifrador = AES.new(clave, modo, nonce=nonce)  # Usar el mismo nonce
        elif modo == AES.MODE_CBC:
            cifrador = AES.new(clave, modo, iv)  # Usar el mismo IV
        else:  # ECB
            cifrador = AES.new(clave, modo)
        
        texto_cifrado2 = cifrador.encrypt(bytes(texto_plano_modificado) if modo == AES.MODE_CTR else pad(bytes(texto_plano_modificado), AES.block_size))
        diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))
        cambios_bits.append(diferencia_bits)
    
    cambio_promedio_bits = sum(cambios_bits) / len(cambios_bits)

    return cambio_promedio_bits, (cambio_promedio_bits / 128) * 100


def probar_sensibilidad_clave(modo):

    clave1 = get_random_bytes(16)
    clave2 = bytearray(clave1)
    clave2[0] ^= 1  # Cambiar un bit en la clave
    texto_plano = b'Este es un mensaje de prueba para sensibilidad de clave'
    
    if modo == AES.MODE_CTR:
        nonce = get_random_bytes(8)
        cifrador1 = AES.new(clave1, modo, nonce=nonce)
        cifrador2 = AES.new(bytes(clave2), modo, nonce=nonce)  # Usar el mismo nonce
    elif modo == AES.MODE_CBC:
        iv = get_random_bytes(AES.block_size)
        cifrador1 = AES.new(clave1, modo, iv)
        cifrador2 = AES.new(bytes(clave2), modo, iv)  # Usar el mismo IV
    else:  
        cifrador1 = AES.new(clave1, modo)
        cifrador2 = AES.new(bytes(clave2), modo)
    
    texto_cifrado1 = cifrador1.encrypt(texto_plano if modo == AES.MODE_CTR else pad(texto_plano, AES.block_size))
    texto_cifrado2 = cifrador2.encrypt(texto_plano if modo == AES.MODE_CTR else pad(texto_plano, AES.block_size))
    diferencia_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(texto_cifrado1, texto_cifrado2))

    return diferencia_bits, (diferencia_bits / len(texto_cifrado1) / 8) * 100


def probar_patron_visual(modo, clave):

    texto_plano = b'A' * 64 + b'B' * 64 + b'C' * 64 + b'D' * 64
    
    if modo == AES.MODE_CTR:
        nonce = get_random_bytes(8)
        cifrador = AES.new(clave, modo, nonce=nonce)
    elif modo == AES.MODE_CBC:
        iv = get_random_bytes(AES.block_size)
        cifrador = AES.new(clave, modo, iv)
    else:  
        cifrador = AES.new(clave, modo)
    
    texto_cifrado = cifrador.encrypt(texto_plano)
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


def main():
    modos = [
        (AES.MODE_ECB, "Modo AES ECB:"),
        (AES.MODE_CBC, "Modo AES CBC:"),
        (AES.MODE_CTR, "Modo AES CTR:")
    ]
    tamaños_datos = {
        "16 bytes": b'Esto es 16 bytes.',
        "128 bytes": b'Este es un mensaje de 128 bytes para cifrado AES. ' * 2,
        "1024 bytes": b'Este es un mensaje de 1024 bytes para cifrado AES. ' * 16
    }
    clave = get_random_bytes(16)

    for modo, nombre_modo in modos:
        print(f"\n{nombre_modo}")
        print("Prueba de rendimiento:")
        for nombre_tamano, datos in tamaños_datos.items():
            print(f"Tamaño de datos: {nombre_tamano}")
            tiempo_promedio_cifrado, tiempo_promedio_descifrado = probar_rendimiento(modo, datos, clave)
            print(f"Tiempo promedio de cifrado: {tiempo_promedio_cifrado:.6f} ms")
            print(f"Tiempo promedio de descifrado: {tiempo_promedio_descifrado:.6f} ms")

        print("\nPrueba de difusión:")
        cambio_promedio_bits, porcentaje_cambiado = probar_difusion(modo, clave)
        print(f"Cambios promedio de bits: {cambio_promedio_bits:.2f} de 128 bits")
        print(f"Porcentaje cambiado: {porcentaje_cambiado:.2f}%")

        print("\nPrueba de sensibilidad de clave:")
        diferencia_bits, porcentaje_diferente = probar_sensibilidad_clave(modo)
        print(f"Bits diferentes en el texto cifrado: {diferencia_bits} de {128 * 8}")
        print(f"Porcentaje diferente: {porcentaje_diferente:.2f}%")

        print("\nPrueba de patrón visual:")
        probar_patron_visual(modo, clave)

        print("\n" + "="*50)

if __name__ == "__main__":
    main()