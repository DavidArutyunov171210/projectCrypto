# projectCrypto
#include <iostream>
#include <openssl/aes.h>
#include <cstring>
#include <fstream>
#include <string>

using namespace std;

void handleErrors() {
    cerr << "Error occurred!" << endl;
    exit(EXIT_FAILURE);
}

void pad(unsigned char *input, size_t &length) {
    size_t padding_length = AES_BLOCK_SIZE - (length % AES_BLOCK_SIZE);
    for (size_t i = length; i < length + padding_length; ++i) {
        input[i] = static_cast<unsigned char>(padding_length);
    }
    length += padding_length;
}

void AES_encrypt_decrypt(const unsigned char *key, const unsigned char *input, unsigned char *output, size_t length, bool encrypt) {
    AES_KEY aesKey;
    if (encrypt) {
        if (AES_set_encrypt_key(key, 128, &aesKey) < 0) handleErrors();
        for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
            AES_encrypt(input + i, output + i, &aesKey);
        }
    } else {
        if (AES_set_decrypt_key(key, 128, &aesKey) < 0) handleErrors();
        for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
            AES_decrypt(input + i, output + i, &aesKey);
        }
    }
}

int main() {
    unsigned char key[AES_BLOCK_SIZE];
    string inputf, temp_k, input, outputf;

    cout << "Введите путь к файлу: ";
    getline(cin, inputf);

    cout << "Введите путь к выходному файлу: ";
    getline(cin, outputf);

    ifstream file(inputf);

    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            input += line + '\n';
        }
        input.pop_back();
    } else {
        cerr << "Не удалось открыть файл: " << inputf << endl;
        return 1;
    }

    cout << "Введите ключ (до 16 символов): ";
    getline(cin, temp_k);
    if (temp_k.size() > 16) {
        temp_k = temp_k.substr(0, 16);
    } else if (temp_k.size() < 16) {
        int sz = temp_k.size();
        for (size_t i = 0; i < 16 - sz; i++) {
            temp_k.push_back('0');
        }
    }
    cout << "Ключ: " << temp_k << endl;
    for (int i = 0; i < 16; i++) {
        key[i] = temp_k[i];
    }

    size_t length = input.length();
    unsigned char *plaintext = new unsigned char[length + AES_BLOCK_SIZE];
    memcpy(plaintext, input.c_str(), length);
    pad(plaintext, length);
    unsigned char *ciphertext = new unsigned char[length];
    unsigned char *decryptedtext = new unsigned char[length];

    int choice;
    cout << "Вы хотите шифровать(1) или расшифровать(2) текст?" << endl;
    cin >> choice;

    if (choice == 1) {
        AES_encrypt_decrypt(key, plaintext, ciphertext, length, true);
        string res;
        for (size_t i = 0; i < length; i++) {
            res.push_back(ciphertext[i]);
        }
        ofstream f(outputf);
        f.write(res.c_str(), res.size());
        f.close();
        cout << "Зашифрованный текст сохранен в файл " << outputf << endl;
    } else if (choice == 2) {
        AES_encrypt_decrypt(key, plaintext, decryptedtext, length, false);
        size_t padding_length = decryptedtext[length - 1];
        string decrypted_string(reinterpret_cast<char*>(decryptedtext), length - padding_length);
        ofstream f(outputf);
        f.write(decrypted_string.c_str(), decrypted_string.size());
        f.close();
        cout << "Расшифрованный текст сохранен в файл " << outputf << endl;
    } else {
        cout << "Неверный выбор. Пожалуйста, введите '1' для шифрования или '2' для расшифрования." << endl;
    }

    delete[] plaintext;
    delete[] ciphertext;
    delete[] decryptedtext;

    return 0;
}