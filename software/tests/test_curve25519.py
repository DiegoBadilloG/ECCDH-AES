import secrets
import time
from src.dh.curve25519 import generar_par_claves_25519, calcular_secreto_compartido_25519, x25519, P, ajustar


def prueba_vectores():

    print("\n----- Prueba de Vectores Curve25519 -----")
    clave_privada_alice = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    clave_publica_alice_esperada = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
    clave_privada_bob = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
    clave_publica_bob_esperada = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
    secreto_compartido_esperado = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')

    clave_publica_alice_calculada = x25519(clave_privada_alice, (9).to_bytes(32, 'little'))
    clave_publica_bob_calculada = x25519(clave_privada_bob, (9).to_bytes(32, 'little'))
    print(f"Clave privada de Alice: {clave_privada_alice.hex()}")
    print(f"Clave pública esperada de Alice: {clave_publica_alice_esperada.hex()}")
    print(f"Clave pública calculada de Alice: {clave_publica_alice_calculada.hex()}")
    print(f"Clave privada de Bob: {clave_privada_bob.hex()}")
    print(f"Clave pública esperada de Bob: {clave_publica_bob_esperada.hex()}")
    print(f"Clave pública calculada de Bob: {clave_publica_bob_calculada.hex()}")

    assert clave_publica_alice_calculada == clave_publica_alice_esperada, "La clave pública de Alice no coincide con el valor esperado"
    assert clave_publica_bob_calculada == clave_publica_bob_esperada, "La clave pública de Bob no coincide con el valor esperado"
    secreto_compartido_alice = x25519(clave_privada_alice, clave_publica_bob_esperada)
    secreto_compartido_bob = x25519(clave_privada_bob, clave_publica_alice_esperada)
    print(f"Secreto compartido esperado: {secreto_compartido_esperado.hex()}")
    print(f"Secreto compartido calculado: {secreto_compartido_alice.hex()}")
    assert secreto_compartido_alice == secreto_compartido_bob, "Los secretos compartidos no coinciden"
    assert secreto_compartido_alice == secreto_compartido_esperado, "El secreto compartido no coincide con el valor esperado"

    print("¡Prueba de vectores pasada con éxito!")


def prueba_integracion():

    print("\n----- Prueba de Integración Curve25519 -----")
    clave_privada_alice, clave_publica_alice = generar_par_claves_25519()
    clave_privada_bob, clave_publica_bob = generar_par_claves_25519()
    secreto_compartido_alice = calcular_secreto_compartido_25519(clave_privada_alice, clave_publica_bob)
    secreto_compartido_bob = calcular_secreto_compartido_25519(clave_privada_bob, clave_publica_alice)
    print(f"Secreto compartido de Alice: {secreto_compartido_alice.hex()}")
    print(f"Secreto compartido de Bob: {secreto_compartido_bob.hex()}")
    assert secreto_compartido_alice == secreto_compartido_bob, "Los secretos compartidos no coinciden"

    print("Verificación del secreto compartido exitosa.")


def verificaciones_seguridad():

    print("\n----- Verificaciones de Seguridad Curve25519 -----")
    clave_privada, clave_publica = generar_par_claves_25519()
    assert len(clave_privada) == 32, "La clave privada debe tener 32 bytes"
    assert len(clave_publica) == 32, "La clave pública debe tener 32 bytes"
    print("Longitudes de clave correctas.")
    clave_privada_int = int.from_bytes(clave_privada, 'little')
    assert 0 < clave_privada_int < 2**256, "La clave privada está fuera del rango válido"
    print("La clave privada está en el rango válido.")
    clave_publica_int = int.from_bytes(clave_publica, 'little')
    assert 0 <= clave_publica_int < P, "La clave pública está fuera del rango válido"

    print("La clave pública está en el rango válido.")

    # Prueba de ajuste
    clave_ajustada = ajustar(clave_privada_int)
    assert clave_ajustada & 0x7 == 0, "La clave ajustada debe tener los 3 bits más bajos en cero"
    assert clave_ajustada & (1 << 254) != 0, "La clave ajustada debe tener el bit 254 en uno"
    assert clave_ajustada & (1 << 255) == 0, "La clave ajustada debe tener el bit 255 en cero"

    print("La función de ajuste funciona correctamente.")


def prueba_casos_limite():

    print("\n----- Prueba de Casos Límite Curve25519 -----")
    clave_publica_cero = b'\x00' * 32
    clave_privada_aleatoria, _ = generar_par_claves_25519()

    try:
        calcular_secreto_compartido_25519(clave_privada_aleatoria, clave_publica_cero)
        print("Error: La clave pública de ceros debería ser rechazada")
    except ValueError as e:
        print(f"Prueba pasada. Error esperado: {str(e)}")

    clave_privada_cero = b'\x00' * 32
    clave_publica_aleatoria = generar_par_claves_25519()[1]
    resultado = calcular_secreto_compartido_25519(clave_privada_cero, clave_publica_aleatoria)
    assert resultado != b'\x00' * 32, "El secreto compartido no debe ser todo ceros para una clave privada de ceros"
    print("Prueba de clave privada de ceros pasada.")
    print(f"Resultado con clave privada de ceros: {resultado.hex()}")


def pruebas_rendimiento():

    print("\n----- Pruebas de Rendimiento Curve25519 -----")
    num_operaciones = 1000
    inicio_tiempo = time.time()

    for _ in range(num_operaciones):
        generar_par_claves_25519()

    tiempo_par_claves = time.time() - inicio_tiempo
    inicio_tiempo = time.time()
    clave_privada, clave_publica = generar_par_claves_25519()

    for _ in range(num_operaciones):
        calcular_secreto_compartido_25519(clave_privada, clave_publica)
    
    tiempo_secreto_compartido = time.time() - inicio_tiempo
    print(f"Tiempo para generar {num_operaciones} pares de claves: {tiempo_par_claves:.4f} segundos")
    print(f"Tiempo promedio por par de claves: {tiempo_par_claves/num_operaciones:.6f} segundos")
    print(f"Pares de claves por segundo: {num_operaciones/tiempo_par_claves:.2f}")
    print(f"Tiempo para calcular {num_operaciones} secretos compartidos: {tiempo_secreto_compartido:.4f} segundos")
    print(f"Tiempo promedio por secreto compartido: {tiempo_secreto_compartido/num_operaciones:.6f} segundos")
    print(f"Secretos compartidos por segundo: {num_operaciones/tiempo_secreto_compartido:.2f}")


def prueba_manejo_errores():

    print("\n----- Prueba de Manejo de Errores Curve25519 -----")
    try:
        calcular_secreto_compartido_25519(b'clave_corta', b'clave_publica_valida' * 2)
        print("Error: Debería haber rechazado una clave privada corta")
    except ValueError as e:
        print(f"Prueba pasada. Error esperado: {str(e)}")

    try:
        calcular_secreto_compartido_25519(b'clave_privada_valida' * 2, b'clave_corta')
        print("Error: Debería haber rechazado una clave pública corta")
    except ValueError as e:
        print(f"Prueba pasada. Error esperado: {str(e)}")


def prueba_multiple_iteracion():

    print("\n----- Prueba de Múltiples Iteraciones Curve25519 -----")
    clave_privada_alice, clave_publica_alice = generar_par_claves_25519()
    clave_privada_bob, clave_publica_bob = generar_par_claves_25519()
    resultados = set()

    for _ in range(100):
        secreto_compartido_alice = calcular_secreto_compartido_25519(clave_privada_alice, clave_publica_bob)
        resultados.add(secreto_compartido_alice)
   
    assert len(resultados) == 1, "El secreto compartido debería ser consistente en múltiples cálculos"
    print("Prueba de múltiples iteraciones pasada con éxito.")


def prueba_resistencia_timing():

    print("\n----- Prueba de Resistencia a Ataques de Timing Curve25519 -----")
    clave_privada, _ = generar_par_claves_25519()
    clave_publica1 = b'\x01' * 32
    clave_publica2 = b'\xff' * 32
    tiempos = []

    for _ in range(1000):
        inicio = time.time()
        calcular_secreto_compartido_25519(clave_privada, clave_publica1)
        fin = time.time()
        tiempos.append(fin - inicio)

    tiempo_promedio1 = sum(tiempos) / len(tiempos)
    tiempos = []

    for _ in range(1000):
        inicio = time.time()
        calcular_secreto_compartido_25519(clave_privada, clave_publica2)
        fin = time.time()
        tiempos.append(fin - inicio)

    tiempo_promedio2 = sum(tiempos) / len(tiempos)
    diferencia_tiempo = abs(tiempo_promedio1 - tiempo_promedio2)
    print(f"Diferencia de tiempo promedio: {diferencia_tiempo:.6f} segundos")
    assert diferencia_tiempo < 0.001, "La diferencia de tiempo no debería ser significativa"

    print("Prueba de resistencia a ataques de timing pasada con éxito.")


def ejecutar_todas_las_pruebas():
    prueba_vectores()
    prueba_integracion()
    verificaciones_seguridad()
    prueba_casos_limite()
    pruebas_rendimiento()
    prueba_manejo_errores()
    prueba_multiple_iteracion()
    prueba_resistencia_timing()

if __name__ == "__main__":
    ejecutar_todas_las_pruebas()