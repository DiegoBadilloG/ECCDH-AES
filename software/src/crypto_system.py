# Integra el cifrado AES-CTR con el intercambio de claves Diffie-Hellman


import secrets
from typing import Tuple, Union
from .aes import cifrar_ctr, descifrar_ctr
from .dh import generar_par_claves_25519, calcular_secreto_compartido_25519, generar_par_claves_secp256r1, calcular_secreto_compartido_secp256r1
from .kdf import derivar_clave


class SistemaCriptografico:
    
    def __init__(self, curva: str = '25519'):

        self.curva = curva
        if curva == '25519':
            self.generar_par_claves = generar_par_claves_25519
            self.calcular_secreto_compartido = calcular_secreto_compartido_25519
        elif curva == 'secp256r1':
            self.generar_par_claves = generar_par_claves_secp256r1
            self.calcular_secreto_compartido = calcular_secreto_compartido_secp256r1
        else:
            raise ValueError("Curva no soportada. Usa '25519' o 'secp256r1'.")

    def generar_claves(self) -> Tuple[Union[bytes, int], Union[bytes, Tuple[int, int]]]:

        return self.generar_par_claves()

    def _formatear_secreto_compartido(self, secreto_compartido: Union[bytes, int]) -> str:
        if isinstance(secreto_compartido, bytes):
            return '0x' + secreto_compartido.hex()
        elif isinstance(secreto_compartido, int):
            return hex(secreto_compartido)
        else:
            raise ValueError("Formato de secreto compartido no soportado")

    def _validar_clave(self, clave: Union[bytes, int, Tuple[int, int]]) -> None:
        if self.curva == '25519':
            if not isinstance(clave, bytes) or len(clave) != 32:
                raise TypeError("Las claves para Curve25519 deben ser bytes de 32 bytes")
        elif self.curva == 'secp256r1':
            if not (isinstance(clave, int) or (isinstance(clave, tuple) and len(clave) == 2 and all(isinstance(x, int) for x in clave))):
                raise TypeError("Las claves para secp256r1 deben ser enteros o tuplas de dos enteros")

    def cifrar_mensaje(self, clave_privada_emisor: Union[bytes, int], 
                       clave_publica_receptor: Union[bytes, Tuple[int, int]], 
                       mensaje: str) -> Tuple[bytes, bytes]:
        self._validar_clave(clave_privada_emisor)
        self._validar_clave(clave_publica_receptor)
        secreto_compartido = self.calcular_secreto_compartido(clave_privada_emisor, clave_publica_receptor)
        secreto_formateado = self._formatear_secreto_compartido(secreto_compartido)
        clave_aes = derivar_clave(secreto_formateado)
        clave_aes_bytes = bytes.fromhex(clave_aes[2:])
        nonce = secrets.token_bytes(8)
        texto_cifrado = cifrar_ctr(mensaje.encode(), clave_aes_bytes, nonce)

        return nonce, texto_cifrado

    def descifrar_mensaje(self, clave_privada_receptor: Union[bytes, int], 
                          clave_publica_emisor: Union[bytes, Tuple[int, int]], 
                          nonce: bytes, texto_cifrado: bytes) -> str:
        self._validar_clave(clave_privada_receptor)
        self._validar_clave(clave_publica_emisor)
        secreto_compartido = self.calcular_secreto_compartido(clave_privada_receptor, clave_publica_emisor)
        secreto_formateado = self._formatear_secreto_compartido(secreto_compartido)
        clave_aes = derivar_clave(secreto_formateado)
        clave_aes_bytes = bytes.fromhex(clave_aes[2:])
        texto_plano = descifrar_ctr(texto_cifrado, clave_aes_bytes, nonce)

        return texto_plano.decode()