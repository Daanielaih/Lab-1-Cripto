from scapy.all import sniff, ICMP
import time
from scapy.all import conf, L3RawSocket  # <-- Add this line

conf.L3socket = L3RawSocket  # <-- And this line

# --- DESCIFRADO CÉSAR ---
def descifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            inicio = ord('A') if char.isupper() else ord('a')
            nuevo = (ord(char) - inicio - corrimiento) % 26 + inicio
            resultado += chr(nuevo)
        else:
            resultado += char
    return resultado

# --- DETECTAR LA OPCIÓN MÁS PROBABLE ---
def opcion_mas_probable(lista_descifrados):
    max_score = -1
    mejor_opcion = None
    for t in lista_descifrados:
        score = len(re.findall(r'[A-Za-z ]', t))
        if score > max_score:
            max_score = score
            mejor_opcion = t
    return mejor_opcion

# --- LISTA PARA ALMACENAR EL MENSAJE CIFRADO ---
mensaje_cifrado = []

# --- TIEMPO PARA DETENER LA ESCUCHA SI NO LLEGAN PAQUETES ---
ULTIMO_PAQUETE = time.time()
TIMEOUT = 8  # segundos sin recibir paquete para detener

def procesar_paquete(paquete):
    global ULTIMO_PAQUETE
    if ICMP in paquete:
        payload = bytes(paquete[ICMP].payload)
        if len(payload) > 0:
            mensaje_cifrado.append(chr(payload[0]))
            print(f"Recibido carácter cifrado: {chr(payload[0])}")
            ULTIMO_PAQUETE = time.time()  # actualizar tiempo del último paquete recibido

# --- PROGRAMA PRINCIPAL ---
if __name__ == "__main__":
    print("Escuchando paquetes ICMP...")

    # Sniff con timeout dinámico
    while True:
        sniff(iface="lo0", filter="icmp", prn=procesar_paquete, timeout=1)
        if time.time() - ULTIMO_PAQUETE > TIMEOUT:
            print("\nTiempo de espera superado. Finalizando escucha.")
            break

    # Reconstruir mensaje cifrado completo
    mensaje = "".join(mensaje_cifrado)
    print("\nMensaje cifrado completo:", mensaje)

    # Pruebas
    resultados = []
    for corrimiento in range(26):
        descifrado = descifrado_cesar(mensaje, corrimiento)
        resultados.append((corrimiento, descifrado))

    # Detectar opción más probable
    mejor = opcion_mas_probable([r[1] for r in resultados])

    # Mostrar todos los resultados
    print("\nResultados posibles:")
    for corrimiento, texto in resultados:
        if texto == mejor:
            print(f"\033[92mCorrimiento {corrimiento}: {texto}\033[0m")  # Verde
        else:
            print(f"Corrimiento {corrimiento}: {texto}")
