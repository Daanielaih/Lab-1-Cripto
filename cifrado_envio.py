from scapy.all import IP, ICMP, send
import time

# --- CIFRADO CÉSAR ---
def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            inicio = ord('A') if char.isupper() else ord('a')
            nuevo = (ord(char) - inicio + corrimiento) % 26 + inicio
            resultado += chr(nuevo)
        else:
            resultado += char
    return resultado

# --- ENVÍO ICMP CON PADDING EXACTO DE 43 BYTES (termina en 0x33) ---
def enviar_mensaje_icmp(destino, mensaje, delay=1):
    """
    Envía un mensaje carácter por carácter en paquetes ICMP Echo Request.
    Cada payload será de 44 bytes: 1 carácter + 43 bytes de padding.
    """
    # Padding recortado: 43 bytes, termina en 0x33
    # Original: 08 09 ... 32 33 (44 bytes) → cortamos 08 para que quepan 43 bytes
    modified_padding = bytes(range(9, 52))  # 9..51 decimal → 43 bytes
    assert len(modified_padding) == 43, f"Padding mal formado: {len(modified_padding)} bytes"

    for i, caracter in enumerate(mensaje):
        # Primer byte = la letra a enviar
        dato = bytes(caracter, "utf-8")
        # Payload total = letra (1 byte) + padding (43 bytes) = 44 bytes
        payload = dato + modified_padding
        assert len(payload) == 44, f"Payload final mal formado: {len(payload)} bytes"

        paquete = IP(dst=destino)/ICMP(id=0x1234, seq=i)/payload
        print(f"Enviando carácter '{caracter}' con payload total {len(payload)} bytes (seq={i})")
        send(paquete, verbose=False)
        time.sleep(delay)

# --- PROGRAMA PRINCIPAL ---
if __name__ == "__main__":
    destino = input("IP destino: ")
    texto = input("cifrar y enviar: ")
    corrimiento = int(input("corrimiento: "))

    # 1) Cifrar el texto
    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print("Texto cifrado:", texto_cifrado)

    # 2) Enviar texto cifrado por ICMP
    enviar_mensaje_icmp(destino, texto_cifrado)
