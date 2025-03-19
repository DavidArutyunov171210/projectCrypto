from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Функция расшифровки файла
def decrypt_file(input_file, output_file, private_key_file):
    # Загружаем приватный ключ
    with open(private_key_file, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    # Чтение зашифрованного файла
    with open(input_file, "rb") as f:
        encrypted_aes_key = f.read(256)  # Зашифрованный AES-ключ (2048 битный ключ RSA)
        iv = f.read(12)  # IV для AES (12 байт для GCM)
        tag = f.read(16)  # Тег для GCM
        ciphertext = f.read()  # Зашифрованный текст

    # Расшифровка AES-ключа с использованием RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка файла с помощью AES
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher_aes.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Проверяем расширение входного файла, чтобы сохранить с тем же расширением
    file_extension = os.path.splitext(input_file)[1]  # Получаем расширение входного файла
    output_file_with_extension = output_file if output_file.endswith(file_extension) else output_file + file_extension

    # Сохранение расшифрованного файла в двоичном формате
    with open(output_file_with_extension, "wb") as out_file:  # Используем "wb" для двоичного файла
        out_file.write(plaintext)

    print(" Файл успешно расшифрован:", output_file_with_extension)

# Пример использования
decrypt_file("encrypted_file.bin", "decrypted_file", "private_key.pem")