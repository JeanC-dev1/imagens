from PIL import Image
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# Função para gerar uma chave pública e privada RSA
def gerar_chaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Função para salvar as chaves em arquivos
def salvar_chaves(private_key, public_key):
    # Salvando a chave privada
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Salvando a chave pública
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Função para carregar a chave privada
def carregar_chave_privada():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

# Função para carregar a chave pública
def carregar_chave_publica():
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

# Função para criptografar a mensagem
def encriptar_mensagem(public_key, mensagem):
    encrypted = public_key.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Função para descriptografar a mensagem
def decriptar_mensagem(private_key, mensagem_encriptada):
    decrypted = private_key.decrypt(
        mensagem_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Função para calcular o hash de uma imagem
def calcular_hash_imagem(imagem_path):
    with open(imagem_path, "rb") as f:
        img_data = f.read()
    return hashlib.sha256(img_data).hexdigest()

# Função para embutir texto na imagem utilizando Steganography
def embutir_texto(imagem_path, texto, imagem_saida_path):
    img = Image.open(imagem_path)
    largura, altura = img.size
    pixels = img.load()

    bin_texto = ''.join(format(ord(c), '08b') for c in texto)
    bin_texto += '1111111111111110'  # Caractere de fim de mensagem
    texto_idx = 0

    for y in range(altura):
        for x in range(largura):
            if texto_idx < len(bin_texto):
                r, g, b = pixels[x, y]
                # Modificar o bit menos significativo
                r = r & ~1 | int(bin_texto[texto_idx])
                pixels[x, y] = (r, g, b)
                texto_idx += 1
            else:
                break

    img.save(imagem_saida_path)
    print(f"Texto embutido com sucesso na imagem: {imagem_saida_path}")

# Função para recuperar texto embutido na imagem utilizando Steganography
def recuperar_texto(imagem_path):
    img = Image.open(imagem_path)
    largura, altura = img.size
    pixels = img.load()

    bin_texto = ""
    for y in range(altura):
        for x in range(largura):
            r, g, b = pixels[x, y]
            bin_texto += str(r & 1)  # Extrair o bit menos significativo

            # Se encontrar o marcador de fim de mensagem, parar
            if bin_texto[-16:] == '1111111111111110':
                bin_texto = bin_texto[:-16]  # Remover o marcador
                break
        else:
            continue
        break

    # Converter o binário de volta para texto
    texto = ''.join(chr(int(bin_texto[i:i + 8], 2)) for i in range(0, len(bin_texto), 8))
    return texto

# Função principal para exibir o menu e interagir com o usuário
def menu():
    while True:
        print("\nMenu de opções:")
        print("1 - Embutir texto em uma imagem")
        print("2 - Recuperar texto da imagem")
        print("3 - Gerar o hash das imagens")
        print("4 - Encriptar a mensagem e embutir na imagem")
        print("5 - Decriptar a mensagem de uma imagem")
        print("S - Sair")

        opcao = input("Escolha uma opção: ")

        if opcao == '1':
            imagem_path = input("Caminho da imagem original: ")
            texto = input("Digite o texto a ser embutido: ")
            imagem_saida_path = input("Caminho da imagem de saída: ")
            embutir_texto(imagem_path, texto, imagem_saida_path)

        elif opcao == '2':
            imagem_path = input("Caminho da imagem: ")
            texto_recuperado = recuperar_texto(imagem_path)
            print("Texto recuperado:", texto_recuperado)

        elif opcao == '3':
            imagem_path_original = input("Caminho da imagem original: ")
            imagem_path_alterada = input("Caminho da imagem alterada: ")
            hash_original = calcular_hash_imagem(imagem_path_original)
            hash_alterada = calcular_hash_imagem(imagem_path_alterada)
            print("Hash da imagem original:", hash_original)
            print("Hash da imagem alterada:", hash_alterada)

        elif opcao == '4':
            public_key = carregar_chave_publica()
            texto = input("Digite o texto a ser encriptado: ")
            imagem_path = input("Caminho da imagem original: ")
            imagem_saida_path = input("Caminho da imagem de saída: ")
            mensagem_encriptada = encriptar_mensagem(public_key, texto)
            embutir_texto(imagem_path, mensagem_encriptada.hex(), imagem_saida_path)
            print("Texto encriptado e embutido na imagem com sucesso!")

        elif opcao == '5':
            private_key = carregar_chave_privada()
            imagem_path = input("Caminho da imagem com texto encriptado: ")
            mensagem_hex = recuperar_texto(imagem_path)
            mensagem_encriptada = bytes.fromhex(mensagem_hex)
            texto_decriptado = decriptar_mensagem(private_key, mensagem_encriptada)
            print("Texto decriptado:", texto_decriptado)

        elif opcao in ['S', 's']:
            print("Saindo...")
            break
        else:
            print("Opção inválida, tente novamente.")

if __name__ == "__main__":
    # Gerar e salvar as chaves se necessário
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("Gerando novas chaves RSA...")
        private_key, public_key = gerar_chaves()
        salvar_chaves(private_key, public_key)

    menu()