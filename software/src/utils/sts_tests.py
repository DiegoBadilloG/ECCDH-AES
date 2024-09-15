'''Este módulo implementa una versión simplificada de las pruebas estadísticas (STS - Simplified Test Suite)
recomendadas por el NIST para evaluar la calidad de la aleatoriedad en secuencias de bits cifradas.'''

from scipy import stats
from scipy.special import erfc
import itertools

def prueba_frecuencia(texto_cifrado):

    bits = [int(bit) for byte in texto_cifrado for bit in f'{byte:08b}']
    n = len(bits)
    suma_unos = sum(bits)
    s_obs = abs(suma_unos - (n/2)) / (n/2)**0.5 # Estadístico observado

    return 2 * (1 - stats.norm.cdf(s_obs))


def prueba_rachas(texto_cifrado):

    bits = [int(bit) for byte in texto_cifrado for bit in f'{byte:08b}']
    n = len(bits)
    suma_unos = sum(bits)
    total_rachas = 1 + sum(bits[i] != bits[i+1] for i in range(n-1))
    r_obs = abs(total_rachas - (2*suma_unos*(n-suma_unos)/n)) # Estadístico observado
    r_obs /= (2 * ((2*suma_unos*(n-suma_unos))/(n-1))**0.5)

    return erfc(r_obs)


def prueba_racha_mas_larga(texto_cifrado, tam_bloque=10000):

    bits = [int(bit) for byte in texto_cifrado for bit in f'{byte:08b}']
    n = len(bits)
    num_bloques = n // tam_bloque
    if num_bloques == 0:
        raise ValueError("Texto cifrado demasiado corto para esta prueba")
    
    frecuencias = [0] * 7

    for i in range(num_bloques):
        bloque = bits[i*tam_bloque:(i+1)*tam_bloque]
        racha_mas_larga = max(len(list(g)) for b, g in itertools.groupby(bloque) if b)
        frecuencias[min(racha_mas_larga, 6)] += 1
    
    prob_esperadas = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
    chi_cuadrado = sum((frecuencias[i] - num_bloques*prob_esperadas[i])**2 / (num_bloques*prob_esperadas[i]) for i in range(7))

    return max(1e-10, 1 - stats.chi2.cdf(chi_cuadrado, 6))


def ejecutar_pruebas_sts(texto_cifrado):
 
    return {
        "Prueba de Frecuencia": prueba_frecuencia(texto_cifrado),
        "Prueba de Rachas": prueba_rachas(texto_cifrado),
        "Prueba de Racha Más Larga": prueba_racha_mas_larga(texto_cifrado)
    }


# Un p-valor > 0.01 se considera aceptable, indicando que no hay evidencia fuerte contra la hipótesis de aleatoriedad