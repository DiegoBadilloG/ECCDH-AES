import hashlib
import hmac

def hkdf(material_clave_entrada, sal=None, info=b"", longitud=16):
    
    # Función de Derivación de Clave basada en HMAC (HKDF)

    if sal is None:
        sal = b"\x00" * 32
    
    # Paso 1: Extraer
    prk = hmac.new(sal, material_clave_entrada, hashlib.sha256).digest()
    
    # Paso 2: Expandir
    temp = b""
    okm = b""
    for i in range(1, (longitud // 32) + 2):
        temp = hmac.new(prk, temp + info + bytes([i]), hashlib.sha256).digest()
        okm += temp
    
    return okm[:longitud]


def derivar_clave(secreto_compartido):

    if isinstance(secreto_compartido, str):
        if secreto_compartido.startswith('0x'):
            secreto_compartido = secreto_compartido[2:]
        if len(secreto_compartido) % 2 != 0:
            secreto_compartido = '0' + secreto_compartido
        try:
            bytes_secreto = bytes.fromhex(secreto_compartido)
        except ValueError:
            raise ValueError("Cadena hexadecimal inválida")
        
    elif isinstance(secreto_compartido, int):
        bytes_secreto = secreto_compartido.to_bytes((secreto_compartido.bit_length() + 7) // 8, byteorder='big')
    else:
        raise ValueError("El secreto compartido debe ser una cadena hexadecimal o un entero")

    clave_derivada = hkdf(
        material_clave_entrada=bytes_secreto,
        sal=None,
        info=b'Derivacion de clave',
        longitud=16  # 16 bytes para AES-128
    )

    return '0x' + clave_derivada.hex()