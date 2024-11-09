import cv2
import numpy as np
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base64

# Steganography Functions
def embed_text_in_image(image_path, text, output_path):
    image = cv2.imread(image_path)
    binary_text = ''.join([format(ord(char), '08b') for char in text]) + '1111111111111110'
    data_index = 0
    for values in image:
        for pixel in values:
            for channel in range(3):
                if data_index < len(binary_text):
                    pixel[channel] = int(format(pixel[channel], '08b')[:-1] + binary_text[data_index], 2)
                    data_index += 1
    cv2.imwrite(output_path, image)
    print(f"Texto embutido com sucesso em {output_path}")

def extract_text_from_image(image_path):
    image = cv2.imread(image_path)
    binary_data = ''
    for values in image:
        for pixel in values:
            for channel in range(3):
                binary_data += format(pixel[channel], '08b')[-1]
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_text = ''
    for byte in all_bytes:
        if byte == '11111110':
            break
        decoded_text += chr(int(byte, 2))
    return decoded_text


# Hash Functions
def generate_image_hash(image_path):
    with open(image_path, 'rb') as img_file:
        image_data = img_file.read()
        hash_value = hashlib.sha256(image_data).hexdigest()
    return hash_value


# Encryption/Decryption Functions
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_message.decode()


# Main Menu
def main_menu():
    private_key, public_key = generate_key_pair()
    while True:
        print("\n=== MENU ===")
        print("(1) Embutir texto em imagem")
        print("(2) Recuperar texto de imagem")
        print("(3) Gerar hash de imagens")
        print("(4) Encriptar mensagem")
        print("(5) Decriptar mensagem")
        print("(S/s) Sair")
        option = input("Escolha uma opção: ").strip().lower()
        
        if option == '1':
            image_path = input("Digite o caminho da imagem original: ")
            text = input("Digite o texto para embutir: ")
            output_path = input("Digite o caminho para salvar a imagem alterada: ")
            embed_text_in_image(image_path, text, output_path)
        
        elif option == '2':
            image_path = input("Digite o caminho da imagem alterada: ")
            extracted_text = extract_text_from_image(image_path)
            print(f"Texto recuperado: {extracted_text}")
        
        elif option == '3':
            original_image = input("Digite o caminho da imagem original: ")
            altered_image = input("Digite o caminho da imagem alterada: ")
            original_hash = generate_image_hash(original_image)
            altered_hash = generate_image_hash(altered_image)
            print(f"Hash da imagem original: {original_hash}")
            print(f"Hash da imagem alterada: {altered_hash}")
        
        elif option == '4':
            message = input("Digite a mensagem para encriptar: ")
            encrypted_message = encrypt_message(public_key, message)
            print(f"Mensagem encriptada: {base64.b64encode(encrypted_message).decode()}")
        
        elif option == '5':
            encrypted_message = input("Digite a mensagem encriptada (base64): ")
            encrypted_message_bytes = base64.b64decode(encrypted_message)
            decrypted_message = decrypt_message(private_key, encrypted_message_bytes)
            print(f"Mensagem decriptada: {decrypted_message}")
        
        elif option == 's':
            print("Encerrando o programa. Até mais!")
            break
        
        else:
            print("Opção inválida. Tente novamente.")

# Run the application
if __name__ == "__main__":
    main_menu()
