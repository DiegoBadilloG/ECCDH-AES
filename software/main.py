'''
Archivo principal que demuestra el funcionamiento del sistema criptográfico con el modo usado, 
incluyendo ejemplos de uso y pruebas básicas de integración con Curve25519 y secp256r1 en conjunto con AES-CTR.
'''


from src import SistemaCriptografico

def probar_ciclo_completo_cifrado_descifrado():

    for curva in ['25519', 'secp256r1']:
        print(f"\n----- Prueba de integración completa con {curva} -----")
        sistema_cripto = SistemaCriptografico(curva=curva)

        # Generar claves para Alicia y bob
        clave_privada_alicia, clave_publica_alicia = sistema_cripto.generar_claves()
        clave_privada_bob, clave_publica_bob = sistema_cripto.generar_claves()
        # Alicia envía un mensaje a Bob
        mensaje_original = f"Hola bob, este es un mensaje secreto usando {curva}!"
        nonce, texto_cifrado = sistema_cripto.cifrar_mensaje(clave_privada_alicia, clave_publica_bob, mensaje_original)
        # Bob descifra el mensaje de Alicia
        mensaje_descifrado = sistema_cripto.descifrar_mensaje(clave_privada_bob, clave_publica_alicia, nonce, texto_cifrado)

        print(f"Mensaje original: {mensaje_original}")
        print(f"Mensaje descifrado: {mensaje_descifrado}")
        assert mensaje_original == mensaje_descifrado, "El mensaje descifrado no coincide con el original"
        print("Prueba exitosa: El mensaje descifrado coincide con el original.")


def probar_diferentes_mensajes():

    print("\n----- Prueba con diferentes tipos de mensajes -----")
    sistema_cripto = SistemaCriptografico()
    clave_privada_alicia, clave_publica_alicia = sistema_cripto.generar_claves()
    clave_privada_bob, clave_publica_bob = sistema_cripto.generar_claves()

    mensajes = [
        "Mensaje corto",
        "Un mensaje un poco más largo para probar",
        "Un mensaje muy largo " * 100,
        "Mensaje con caracteres especiales: áéíóú ñ @#$%^&*()_+",
        "" 
    ]

    for msg in mensajes:
        nonce, texto_cifrado = sistema_cripto.cifrar_mensaje(clave_privada_alicia, clave_publica_bob, msg)
        descifrado = sistema_cripto.descifrar_mensaje(clave_privada_bob, clave_publica_alicia, nonce, texto_cifrado)
        assert msg == descifrado, f"Fallo con el mensaje: {msg[:20]}..."
        print(f"Éxito: '{msg[:20]}...'")


def probar_manejo_errores():

    print("\n----- Prueba de manejo de errores -----")
    
    try:
        SistemaCriptografico(curva='curva_invalida')
        print("Error: No se levantó ValueError para una curva inválida.")
    except ValueError:
        print("Éxito: Se levantó ValueError para una curva inválida.")

    sistema_cripto = SistemaCriptografico()
    clave_privada_alicia, clave_publica_alicia = sistema_cripto.generar_claves()
    
    try:
        sistema_cripto.cifrar_mensaje("clave_invalida", clave_publica_alicia, "mensaje")
        print("Error: No se levantó TypeError para una clave privada inválida.")
    except TypeError as e:
        print(f"Éxito: Se levantó TypeError para una clave privada inválida. Mensaje: {str(e)}")

    try:
        sistema_cripto.descifrar_mensaje(clave_privada_alicia, "clave_invalida", b'nonce', b'texto_cifrado')
        print("Error: No se levantó TypeError para una clave pública inválida.")
    except TypeError as e:
        print(f"Éxito: Se levantó TypeError para una clave pública inválida. Mensaje: {str(e)}")

    # Prueba adicional para secp256r1
    sistema_cripto_secp = SistemaCriptografico(curva='secp256r1')
    try:
        sistema_cripto_secp.cifrar_mensaje(b'clave_invalida', (1, 2), "mensaje")
        print("Error: No se levantó TypeError para una clave privada inválida en secp256r1.")
    except TypeError as e:
        print(f"Éxito: Se levantó TypeError para una clave privada inválida en secp256r1. Mensaje: {str(e)}")


def ejecutar_todas_las_pruebas():
    probar_ciclo_completo_cifrado_descifrado()
    probar_diferentes_mensajes()
    probar_manejo_errores()

if __name__ == "__main__":
    ejecutar_todas_las_pruebas()