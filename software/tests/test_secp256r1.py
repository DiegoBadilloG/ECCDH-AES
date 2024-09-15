import time
import secrets
from src.dh.secp256r1 import (
    generar_par_claves_secp256r1, calcular_secreto_compartido_secp256r1, multiplicar_punto_por_escalar,
    esta_punto_en_curva, sumar_puntos, G, a, b, p, n
)


def prueba_integracion():

    print("\n----- Prueba de Integración Secp256r1 -----")
    clave_privada_A, clave_publica_A = generar_par_claves_secp256r1()
    clave_privada_B, clave_publica_B = generar_par_claves_secp256r1()
    print("Claves generadas correctamente.")

    secreto_A = calcular_secreto_compartido_secp256r1(clave_privada_A, clave_publica_B)
    secreto_B = calcular_secreto_compartido_secp256r1(clave_privada_B, clave_publica_A)
    print("Secreto compartido calculado.")
    assert secreto_A == secreto_B, "Los secretos compartidos no coinciden"
    print("Verificación del secreto compartido exitosa.")


def verificaciones_seguridad():

    print("\n----- Verificaciones de Seguridad Secp256r1 -----")
    clave_privada_A, clave_publica_A = generar_par_claves_secp256r1()
    clave_privada_B, clave_publica_B = generar_par_claves_secp256r1()

    assert 1 <= clave_privada_A < n-1 and 1 <= clave_privada_B < n-1, "Claves privadas fuera del rango válido"
    print("Claves privadas en rango válido.")
    assert clave_publica_A != (0, 0) and clave_publica_B != (0, 0), "Claves públicas son el punto en el infinito"
    print("Claves públicas no son el punto en el infinito.")
    assert esta_punto_en_curva(clave_publica_A, a, b, p) and esta_punto_en_curva(clave_publica_B, a, b, p), "Claves públicas fuera de la curva"
    print("Claves públicas están en la curva.")
    secreto_A = multiplicar_punto_por_escalar(clave_publica_B, clave_privada_A, a, p)
    secreto_B = multiplicar_punto_por_escalar(clave_publica_A, clave_privada_B, a, p)
    assert esta_punto_en_curva(secreto_A, a, b, p) and esta_punto_en_curva(secreto_B, a, b, p), "Secretos compartidos fuera de la curva"
    print("Secretos compartidos están en la curva.")


def prueba_vectores_nist():

    print("\n----- Prueba de Vectores NIST Secp256r1 -----")
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    Qx_esperado = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    Qy_esperado = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
    print(f"Vector NIST:")
    print(f"d (clave privada) = {d:064x}")
    print(f"Qx esperado       = {Qx_esperado:064x}")
    print(f"Qy esperado       = {Qy_esperado:064x}")
    Q = multiplicar_punto_por_escalar(G, d, a, p)
    Qx_calculado, Qy_calculado = Q
    print(f"\nResultado calculado:")
    print(f"Qx calculado      = {Qx_calculado:064x}")
    print(f"Qy calculado      = {Qy_calculado:064x}")
    
    assert Q == (Qx_esperado, Qy_esperado), "Los resultados no coinciden exactamente"
    print("Prueba de vector NIST exitosa: Los resultados coinciden exactamente.")
    assert esta_punto_en_curva(Q, a, b, p), "El punto calculado no está en la curva"
    print("Verificación adicional: El punto calculado está en la curva.")


def pruebas_casos_limite():

    print("\n----- Pruebas de Casos Límite Secp256r1 -----")
    infinito = (0, 0)

    assert sumar_puntos(infinito, G, a, p) == G, "Suma con punto en el infinito incorrecta"
    print("Prueba de suma con punto en el infinito exitosa.")
    assert multiplicar_punto_por_escalar(G, 0, a, p) == infinito, "Multiplicación por 0 incorrecta"
    print("Prueba de multiplicación por 0 exitosa.")
    resultado = multiplicar_punto_por_escalar(G, n, a, p)
    assert resultado == infinito, "Multiplicación por orden de la curva incorrecta"
    print("Prueba de multiplicación por orden de la curva exitosa.")


def pruebas_rendimiento():

    print("\n----- Pruebas de Rendimiento Secp256r1 -----")
    num_operaciones = 100
    tiempo_inicio = time.time()

    for _ in range(num_operaciones):
        generar_par_claves_secp256r1()

    tiempo_fin = time.time()
    tiempo_total = tiempo_fin - tiempo_inicio
    tiempo_promedio = tiempo_total / num_operaciones
    print(f"Tiempo total para {num_operaciones} generaciones de clave: {tiempo_total:.4f} segundos")
    print(f"Tiempo promedio por generación de clave: {tiempo_promedio:.6f} segundos")
    print(f"Generaciones de clave por segundo: {1/tiempo_promedio:.2f}")
    tiempo_inicio = time.time()
    clave_privada, clave_publica = generar_par_claves_secp256r1()

    for _ in range(num_operaciones):
        calcular_secreto_compartido_secp256r1(clave_privada, clave_publica)

    tiempo_fin = time.time()
    tiempo_total = tiempo_fin - tiempo_inicio
    tiempo_promedio = tiempo_total / num_operaciones
    print(f"\nTiempo total para {num_operaciones} cálculos de secreto compartido: {tiempo_total:.4f} segundos")
    print(f"Tiempo promedio por cálculo de secreto compartido: {tiempo_promedio:.6f} segundos")
    print(f"Cálculos de secreto compartido por segundo: {1/tiempo_promedio:.2f}")


def prueba_manejo_errores():

    print("\n----- Prueba de Manejo de Errores Secp256r1 -----")

    try:
        calcular_secreto_compartido_secp256r1(123.45, G)  # Usando un float en lugar de un int
        print("Error: Debería haber rechazado una clave privada inválida")
    except TypeError as e:
        print(f"Prueba pasada. Error esperado: {str(e)}")

    try:
        calcular_secreto_compartido_secp256r1(n, G)
        print("Error: Debería haber rechazado una clave privada fuera de rango")
    except ValueError as e:
        print(f"Prueba pasada. Error esperado: {str(e)}")

    try:
        calcular_secreto_compartido_secp256r1(secrets.randbelow(n), (0, 0))
        print("Error: Debería haber rechazado un punto en el infinito como clave pública")
    except ValueError as e:
        print(f"Prueba pasada. Error esperado: {str(e)}")


def prueba_resistencia_timing():

    print("\n----- Prueba de Resistencia a Ataques de Timing Secp256r1 -----")
    clave_privada, _ = generar_par_claves_secp256r1()
    clave_publica1 = multiplicar_punto_por_escalar(G, 1, a, p)
    clave_publica2 = multiplicar_punto_por_escalar(G, n-1, a, p)
    tiempos = []

    for _ in range(1000):
        inicio = time.time()
        calcular_secreto_compartido_secp256r1(clave_privada, clave_publica1)
        fin = time.time()
        tiempos.append(fin - inicio)

    tiempo_promedio1 = sum(tiempos) / len(tiempos)
    tiempos = []

    for _ in range(1000):
        inicio = time.time()
        calcular_secreto_compartido_secp256r1(clave_privada, clave_publica2)
        fin = time.time()
        tiempos.append(fin - inicio)

    tiempo_promedio2 = sum(tiempos) / len(tiempos)

    diferencia_tiempo = abs(tiempo_promedio1 - tiempo_promedio2)
    print(f"Diferencia de tiempo promedio: {diferencia_tiempo:.6f} segundos")
    assert diferencia_tiempo < 0.001, "La diferencia de tiempo no debería ser significativa"
    print("Prueba de resistencia a ataques de timing pasada con éxito.")


def ejecutar_todas_las_pruebas():
    prueba_integracion()
    verificaciones_seguridad()
    prueba_vectores_nist()
    pruebas_casos_limite()
    pruebas_rendimiento()
    prueba_manejo_errores()
    prueba_resistencia_timing()

if __name__ == "__main__":
    ejecutar_todas_las_pruebas()