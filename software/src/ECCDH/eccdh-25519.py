""" Algoritmo diffie-hellman con la curva 25519 """
""" Ecuacion de la Curva:

Y^2 = X^3 + X^2 * A + X mod P    


El protocolo utiliza punto elíptico comprimido (sólo coordenadas X), por lo que permite un uso eficiente de la 
escalera de Montgomery para ECDH, utilizando sólo coordenadas XZ.

Curve25519 está construida de tal manera que evita muchos problemas potenciales de implementación. Por diseño,
es inmune a los ataques de tiempo y acepta cualquier cadena de 32 bytes como una clave pública válida y no 
requiere validar que un punto dado pertenezca a la curva, o que sea generado por el punto base
"""

import random

#Parametros de la curva
p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
a = 0x76d06
b = 0x01
G = (0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)
n = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
h = 0x08

# Función para sumar dos puntos en la curva elíptica Curve25519
def add_points(point1, point2):
    x1, y1 = point1
    x2, y2 = point2
    
    if point1 == (0, 0):  
        return point2
    elif point2 == (0, 0):
        return point1
    
    if x1 == x2 and (y1 != y2 or y1 == 0):  # Si los puntos son iguales o si están en direcciones opuestas
        return (0, 0) 
    
    if x1 == x2: 
        m = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) 
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, p)  
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    
    return (x3, y3)

# Función para multiplicar un punto por un escalar usando el algoritmo double-and-add
def scalar_multiply(point, scalar):
    result = (0, 0)  
    
    scalar_bin = bin(scalar)[2:]
    
   
    for bit in scalar_bin:
        result = add_points(result, result)  
        
        if bit == '1':
            result = add_points(result, point) 
    
    return result


def is_on_point(point):
    # Curve25519 utiliza claves públicas de 32 bytes
    numero = point
    bytes_numero = numero.to_bytes((numero.bit_length() + 7) // 8, 'big')

    # Comprobar la longitud de los bytes
    longitud_bytes = len(bytes_numero)

    return longitud_bytes == 32


private_A = random.randrange(1, n-1) 
private_B = random.randrange(1, n-1) 

public_A = scalar_multiply(G, private_A)
public_B = scalar_multiply(G, private_B)

secret_A = scalar_multiply(public_B, private_A)
secret_B = scalar_multiply(public_A, private_B)

""" print("private_A: ", private_A)
print("private_B: ", private_B)

print("Public A: ", public_A)
print("Public B: ", public_B)
#print("hex B: ", hex(public_B[0]) +', '+ hex(public_B[1]) )

print("mismo secreto?: ", secret_A == secret_B)

print("pertenece a la curva?: ", is_on_point(secret_A[0])) """

#verificacion sobre FPGA
private_A_FPGA = 0x15ad1f0e7fffffff2965f2fb09753296554518e57fffffff7fffffff7fffffff
#public_B_FPGA = (0x3b69ad7f0bdb28ed45f4080c7c7c784199d2e022d9a3b3ee3020f642c4a15d54, 0x2078ce2c04c8b37f9407d88fb12d5ef15dff24e729b5fa6d1ed9b68d50380d6a)
public_A_FPGA = scalar_multiply(G, private_A_FPGA)
#public_A_FPGA = (0x19aac9a4d41bead36d142f2df21be7ac0c6def4f5f9f67a2a551200c3d8d4f4a, 0x66873f7b1bba2f499e91fd4d034018e835739520f430fd6bfd282599eb212fb7)
public_B_FPGA = public_A_FPGA
secret_A_FPGA = scalar_multiply(public_B_FPGA, private_A_FPGA)

secretAHex = hex(secret_A_FPGA[0])
print("public A FPGA: ", hex(public_A_FPGA[0]) +', '+hex(public_A_FPGA[1]))
print("secret A hex: ", secretAHex)
