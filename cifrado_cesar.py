def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isupper():  # Si es letra mayúscula
            resultado += chr((ord(char) - ord('A') + corrimiento) % 26 + ord('A'))
        elif char.islower():  # Si es letra minúscula
            resultado += chr((ord(char) - ord('a') + corrimiento) % 26 + ord('a'))
        else:
            resultado += char  # Si no es letra, se deja igual
    return resultado

def main():
    texto = input("cifrar: ")
    while True:
        try:
            corrimiento = int(input("corrimiento: "))
            break
        except ValueError:
            print("Por favor, ingrese un número entero válido.")
    
    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print("cifrado:", texto_cifrado)

if __name__ == "__main__":
    main()
