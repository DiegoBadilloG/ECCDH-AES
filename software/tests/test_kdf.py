from src.kdf import derivar_clave

def probar_derivacion_clave():

    print("Probando KDF")
    
    # Prueba con una cadena hexadecimal
    secreto_compartido_hex = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
    clave_derivada = derivar_clave(secreto_compartido_hex)
    print("Prueba 1: Entrada de cadena hexadecimal")
    print("Secreto compartido:", secreto_compartido_hex)
    print("Clave derivada:", clave_derivada)
    assert len(clave_derivada) == 34, "La clave derivada debe ser de 16 bytes (32 caracteres hex + '0x')"
    
    # Prueba con un entero
    secreto_compartido_int = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    clave_derivada = derivar_clave(secreto_compartido_int)
    print("\nPrueba 2: Entrada de entero")
    print("Secreto compartido:", hex(secreto_compartido_int))
    print("Clave derivada:", clave_derivada)
    assert len(clave_derivada) == 34, "La clave derivada debe ser de 16 bytes (32 caracteres hex + '0x')"
    
    # Prueba con una entrada más pequeña
    secreto_compartido_pequeno = '0x1234'
    clave_derivada = derivar_clave(secreto_compartido_pequeno)
    print("\nPrueba 3: Entrada pequeña")
    print("Secreto compartido:", secreto_compartido_pequeno)
    print("Clave derivada:", clave_derivada)
    assert len(clave_derivada) == 34, "La clave derivada siempre debe ser de 16 bytes (32 caracteres hex + '0x')"
    
    # Prueba de manejo de errores
    try:
        derivar_clave("no es una cadena hex ni un entero")
        assert False, "Debería haber lanzado un ValueError"
    except ValueError:
        print("\nPrueba 4: La entrada inválida lanzó correctamente un ValueError")

    print("\nPrueba 5: Verificación de consistencia")
    clave1 = derivar_clave('0x1234')
    clave2 = derivar_clave('0x1234')
    assert clave1 == clave2, "KDF debería producir resultados consistentes para la misma entrada"
    print("Verificación de consistencia pasada")

    print("\nPrueba 6: Diferentes longitudes de entrada")
    entradas = ['0x1', '0x12', '0x123', '0x1234', '0x12345']
    for valor_entrada in entradas:
        clave = derivar_clave(valor_entrada)
        assert len(clave) == 34, f"La clave derivada debe ser de 16 bytes para la entrada {valor_entrada}"
        print(f"Entrada: {valor_entrada}, Clave derivada: {clave}")

    print("\nPrueba 7: Casos límite")
    # Valor máximo para entrada de 256 bits
    entrada_max = '0x' + 'f' * 64
    clave_max = derivar_clave(entrada_max)
    print(f"Entrada máxima: {entrada_max}")
    print(f"Clave derivada: {clave_max}")

    # Valor mínimo 
    entrada_min = '0x1'
    clave_min = derivar_clave(entrada_min)
    print(f"Entrada mínima: {entrada_min}")
    print(f"Clave derivada: {clave_min}")

    print("\nPrueba 8: Entrada más larga de 32 bytes")
    entrada_larga = '0x' + '1234' * 20  # 80 bytes
    try:
        derivar_clave(entrada_larga)
        print("Manejó correctamente la entrada larga")
    except ValueError as e:
        print(f"Lanzó ValueError para entrada larga: {str(e)}")

    print("\nTodas las pruebas pasadas con éxito")

if __name__ == "__main__":
    probar_derivacion_clave()