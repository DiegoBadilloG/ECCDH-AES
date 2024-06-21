""" 
En esta version lo que sae ha hecho es añadir
las operaciones basicas en una curva eliptica:
    -Adicion de puntos
    -Duplicacion de puntos
    -Multiplicacion escalar

Ecucion de la curva: y^2 = x^3 + a*x + b mod P

Formula para suma de puntos: 
    -Si P != Q: 
        s = ( (Qy- Py)/(Qx-Px) ) mod P
        Rx = (s^2 - Px - Qx) mod P
        Ry = ( s*(Px -Rx) - Py ) mod p
    
    -Si P == Q:
        s = (3*(Px)^2 + a)/(2*Py) mod P
        Rx = (s^2 - 2*Px) mod P
        Ry = ( s*(Px - Rx) - Py ) mod P

Formula para de duplicacion de un punto:
    (igual que el apartado anterior )
    s = (3*(Px)^2 + a)/(2*Py) mod P
    Rx = (s^2 - 2*Px) mod P
    Ry = ( s*(Px - Rx) - Py ) mod P

Formula para la muoltiplicacion escalar:
    -incializar un punto R en el 'infinito'
    -expandir el escalar en binario
    -iterar a traves de los bits de derecha a izquierda:
        ·duplicar el punto R
        ·si el bit es 1, sumar el punto base G al punto R
"""

import random

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
h = 0x1

#función para sumar dos puntos en la curva elíptica
def add_points(P, Q, a, p):
    x_p, y_p = P
    x_q, y_q = Q
    """ printed = False """
    if P == (0, 0):  #punto en el "infinito"
        return Q
    elif Q == (0, 0):  
        return P
    elif P == Q:  #duplicación de punto
        s = ((3 * x_p**2 + a) * pow(2 * y_p, -1, p)) % p
    else:  #suma de puntos distintos
        s = ((y_q - y_p) * pow(x_q - x_p, -1, p)) % p
    
    x_r = (s**2 - x_p - x_q) % p
    y_r = (s * (x_p - x_r) - y_p) % p
    
    return (x_r, y_r)

#función para multiplicar un punto por un escalar en la curva elíptica
def multiply_point_by_scalar(point, scalar, a, p):
    result = (0, 0)
    
    #expansión binaria del escalar
    binary_scalar = bin(scalar)[2:]
    
    for bit in binary_scalar:
        result = add_points(result, result, a, p)
        if bit == '1':
            result = add_points(result, point, a, p)
    
    return result

#generación de claves privadas
private_key_A = random.randrange(1, n-1)
private_key_B = random.randrange(1, n-1)

#generacion de claves publicas
public_key_A = multiply_point_by_scalar(G, private_key_A, a, p)
public_key_B = multiply_point_by_scalar(G, private_key_B, a, p)


#generacion de secreto compartido
""" elegimos solo la coordenada X por convencion. Tambien por que X se puede
usar para derivar en una clave simetrica """
secret_A = multiply_point_by_scalar(public_key_B, private_key_A, a, p)
secret_A = secret_A[0]
secreto_B = multiply_point_by_scalar(public_key_A, private_key_B, a, p)
secreto_B = secreto_B[0]

""" print("Clave pública de A:", public_key_A)
print("Clave pública de B:", public_key_B) """

def is_point_on_curve(point, a, b, p):
    x, y = point
    left_side = (y**2) % p
    right_side = (x**3 + a * x + b) % p
    
    return left_side == right_side

#verificación de que las claves publicas estan en la curva
is_A_key_on_curve = is_point_on_curve(public_key_A, a, b, p)
is_B_key_on_curve = is_point_on_curve(public_key_A, a, b, p)
""" print("Clave pública de A en la curva?", is_A_key_on_curve)
print("Clave pública de B en la curva?", is_B_key_on_curve) """

#verificación para datos de la fpga
#private_A_FPGA = 0x15ad1f0e7fffffff2965f2fb09753296554518e57fffffff7fffffff7fffffff
private_A_FPGA = 0x3
public_A_FPGA = multiply_point_by_scalar(G, private_A_FPGA, a, p)
#public_A_FPGA = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d8aa7972, 0x8b5d90bf0c91e1fab33a0ae814aeffb946e76f97d8faec8b7a4cf33ac892c01d)
secret_A_FPGA = multiply_point_by_scalar(public_A_FPGA, private_A_FPGA,a,p)
fpga_point = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
is_fpga_key_on_curve = is_point_on_curve(public_A_FPGA, a, b, p)
print("publica de FPGA: ", hex(public_A_FPGA[0]), hex(public_A_FPGA[1]))
print("Clave pública de la FPGA esta en la curva?", is_fpga_key_on_curve)
""" print("secret_A_FPGA: ", hex(secret_A_FPGA[0]), hex(secret_A_FPGA[1])) """

import math
def inverso(value, modular):
    g0 = modular
    g1 = value 
    u1 = 1
    u2 = 0
    v1 = 0
    v2 = 1
    r = 1

    while r > 0:
        y = g0 / g1
        r = g0 - y * g1
        u3 = u1 - y * u2
        v3 = v1 - y * v2
        if r > 0:
            g0 = g1
            g1 = r
            v1 = v2 
            v2 = v3
            u1 = u2 
            u2 = u3
    if v2 < 0:
        v2 += modular

    return  v2


test1 = 0x12300000000010a25b66fa00000000000000000000000000000000000001111115ad1f0e7fffffff2965f2fb09753296554518e57fffffff7fffffff7fffffff
""" print("pow inv n mod p: (en hex)", (hex(pow(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, -1, p)))) """
""" 0xffe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff """
""" adp = multiply_point_by_scalar((Gx, Gy), private_key_A, a, p)
print("SRL = ", hex(private_key_A))
print("multiply_point_by_scalar:", hex(adp[0]) + ', ' + hex(adp[1])) """
""" tp1 = ( 0x7b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296)
adp =  add_points(tp1, (Gx, Gy), a, p)
print("add_points with P and Q different: ", hex(adp[0]) + ', ' + hex(adp[1])) """

#verificamos que el secreto compartido coincide para A y B
""" print("el secreto compartido es el mismo?:", secret_A == secreto_B) """
#guardamos las claves en un fuchero
route = 'D:/universidad/TFG/cripto-old/diffie-hellman/claves_DH_ECCDH/'
with open(route + 'secp256r1_V3.txt','w') as archivo:
    archivo.write("clave privada de A = " + str(private_key_A) + "\nClave privada de B = " + str(private_key_B) + "\n\n")
    archivo.write("clave publica de A = " + str(public_key_A) + "\nClave publica de B = " + str(public_key_B) + "\n\n")
    archivo.write("Secreto de A = " + str(secret_A) + "\nSecreto de B = " + str(secreto_B))

