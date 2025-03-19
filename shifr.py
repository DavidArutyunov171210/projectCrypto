from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# ======== 1️⃣ Генерация RSA ключей ========
def generate_rsa_keys():
    # Генерация пары ключей RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Сохранение приватного ключа
    with open("private_key.pem", "wb") as private_pem:
        private_pem.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Генерация публичного ключа
    public_key = private_key.public_key()

    # Сохранение публичного ключа
    with open("public_key.pem", "wb") as public_pem:
        public_pem.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(" Ключи RSA успешно созданы!")

# ======== 2️⃣ Шифрование файла с использованием RSA ========
def encrypt_file(input_file, output_file, public_key_file):
    # Загружаем публичный ключ
    with open(public_key_file, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(
            pub_file.read(),
            backend=default_backend()
        )

    # Генерация случайного ключа AES
    aes_key = os.urandom(32)  # 256-битный ключ AES

    # Шифруем AES-ключ с помощью RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Генерация IV (инициализационный вектор) для AES
    iv = os.urandom(12)  # Для GCM обычно 12 байт

    # Шифруем файл с использованием AES
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_aes.encryptor()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Сохраняем зашифрованные данные
    with open(output_file, "wb") as out_file:
        out_file.write(encrypted_aes_key)
        out_file.write(iv)        # Добавляем IV
        out_file.write(tag)       # Добавляем тег
        out_file.write(ciphertext) # Добавляем зашифрованные данные

    print(" Файл успешно зашифрован:", output_file)

# ======== 3️⃣ Расшифровка файла с использованием RSA ========
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
        iv = f.read(12)  # IV для AES
        tag = f.read(16)  # Тег для GCM
        ciphertext = f.read()

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

    # Сохранение расшифрованного файла
    with open(output_file, "wb") as out_file:
        out_file.write(plaintext)

    print(" Файл успешно расшифрован:", output_file)

# ======== 4️⃣ Демонстрация работы ========
if __name__ == "__main__":
    generate_rsa_keys()  # Генерация ключей

    # Зашифровка файла
    File_name = input("какой файл надо зашифровать???")
    encrypt_file(File_name, "encrypted_file.bin", "public_key.pem")

    # Расшифровка файла
    decrypt_file("encrypted_file.bin", "decrypted_file.txt", "private_key.pem")