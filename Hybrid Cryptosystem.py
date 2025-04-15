from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json


class HybridCryptoSystem:
    def __init__(self):
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.session_key = None

    def generate_rsa_keys(self, key_size=2048):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        print(f"Сгенерирована пара ключей RSA размером {key_size} бит")
        return self.rsa_public_key, self.rsa_private_key

    def save_rsa_public_key(self, filename="public_key.pem"):
        if not self.rsa_public_key:
            raise ValueError("Открытый ключ RSA не был сгенерирован")

        public_key_pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(filename, "wb") as f:
            f.write(public_key_pem)
        print(f"Открытый ключ RSA сохранен в файл {filename}")

    def load_rsa_public_key(self, filename="public_key.pem"):
        with open(filename, "rb") as f:
            public_key_pem = f.read()

        self.rsa_public_key = serialization.load_pem_public_key(public_key_pem)
        print(f"Открытый ключ RSA загружен из файла {filename}")
        return self.rsa_public_key

    def save_rsa_private_key(self, filename="private_key.pem", password=None):
        if not self.rsa_private_key:
            raise ValueError("Закрытый ключ RSA не был сгенерирован")

        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()

        private_key_pem = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        with open(filename, "wb") as f:
            f.write(private_key_pem)
        print(f"Закрытый ключ RSA сохранен в файл {filename}")

    def load_rsa_private_key(self, filename="private_key.pem", password=None):
        with open(filename, "rb") as f:
            private_key_pem = f.read()

        if password:
            self.rsa_private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode()
            )
        else:
            self.rsa_private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
        print(f"Закрытый ключ RSA загружен из файла {filename}")
        return self.rsa_private_key


    def generate_session_key(self, key_size=256):
        # Генерируем ключ (32 байта для AES-256)
        self.session_key = os.urandom(key_size // 8)
        print(f"Сгенерирован сеансовый ключ размером {key_size} бит")
        return self.session_key


    def encrypt_session_key(self, session_key=None):
        if session_key is None:
            session_key = self.session_key

        if not session_key:
            raise ValueError("Сеансовый ключ не был задан")

        if not self.rsa_public_key:
            raise ValueError("Открытый ключ RSA не был задан")

        encrypted_key = self.rsa_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Сеансовый ключ зашифрован с помощью RSA")
        return encrypted_key

    def decrypt_session_key(self, encrypted_key):
        if not self.rsa_private_key:
            raise ValueError("Закрытый ключ RSA не был задан")

        decrypted_key = self.rsa_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.session_key = decrypted_key
        print("Сеансовый ключ расшифрован с помощью RSA")
        return decrypted_key


    def encrypt_document(self, plaintext, session_key=None):

        if session_key is None:
            session_key = self.session_key

        if not session_key:
            raise ValueError("Сеансовый ключ не был задан")

        # Генерируем случайный вектор инициализации (IV)
        iv = os.urandom(12)  # 12 байт для GCM

        # Создаем шифр AES в режиме GCM
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        tag = encryptor.tag

        print(f"Документ зашифрован с помощью AES-GCM (размер: {len(plaintext)} байт)")
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

    def decrypt_document(self, encrypted_data, session_key=None):

        if session_key is None:
            session_key = self.session_key

        if not session_key:
            raise ValueError("Сеансовый ключ не был задан")

        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])

        # Создаем шифр AES в режиме GCM
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        print(f"Документ расшифрован с помощью AES-GCM (размер: {len(plaintext)} байт)")
        return plaintext

    def sign_document(self, document):

        if not self.rsa_private_key:
            raise ValueError("Закрытый ключ RSA не был задан")

        if isinstance(document, str):
            document = document.encode('utf-8')

        signature = self.rsa_private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print(f"Создана цифровая подпись для документа (размер подписи: {len(signature)} байт)")
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, document, signature, public_key=None):

        if public_key is None:
            public_key = self.rsa_public_key

        if not public_key:
            raise ValueError("Открытый ключ RSA не был задан")

        if isinstance(document, str):
            document = document.encode('utf-8')

        signature_bytes = base64.b64decode(signature)

        try:
            public_key.verify(
                signature_bytes,
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Цифровая подпись верна")
            return True
        except Exception as e:
            print(f"Ошибка проверки подписи: {e}")
            return False

    def save_encrypted_data(self, encrypted_key, encrypted_data, signature, filename="encrypted.json"):

        encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')

        data = {
            'encrypted_key': encrypted_key_b64,
            'encrypted_data': encrypted_data,
            'signature': signature
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

        print(f"Зашифрованные данные сохранены в файл {filename}")

    def load_encrypted_data(self, filename="encrypted.json"):

        with open(filename, 'r') as f:
            data = json.load(f)

        encrypted_key = base64.b64decode(data['encrypted_key'])
        encrypted_data = data['encrypted_data']
        signature = data['signature']

        print(f"Зашифрованные данные загружены из файла {filename}")
        return encrypted_key, encrypted_data, signature


def demo():
    print("=== ДЕМОНСТРАЦИЯ РАБОТЫ ГИБРИДНОЙ КРИПТОСИСТЕМЫ ===\n")

    crypto = HybridCryptoSystem()

    print("Шаг 1: Генерация ключевой пары RSA")
    crypto.generate_rsa_keys(key_size=2048)
    crypto.save_rsa_public_key("demo_public_key.pem")
    crypto.save_rsa_private_key("demo_private_key.pem")
    print()

    print("Шаг 2: Генерация сеансового ключа для симметричного шифрования")
    session_key = crypto.generate_session_key()
    print()

    print("Шаг 3: Шифрование сеансового ключа с помощью RSA")
    encrypted_key = crypto.encrypt_session_key()
    print()

    print("Шаг 4: Шифрование документа симметричным алгоритмом")
    document = "Это конфиденциальный документ, который будет зашифрован с помощью гибридной криптосистемы."
    encrypted_data = crypto.encrypt_document(document)
    print()

    print("Шаг 5: Формирование цифровой подписи документа")
    signature = crypto.sign_document(document)
    print()

    print("Шаг 6: Сохранение всех данных в файл")
    crypto.save_encrypted_data(encrypted_key, encrypted_data, signature, "demo_encrypted.json")
    print()

    print("=== ИМИТАЦИЯ ПЕРЕДАЧИ ДАННЫХ ===\n")

    receiver = HybridCryptoSystem()

    print("Шаг 7: Загрузка открытого ключа и зашифрованных данных")
    receiver.load_rsa_public_key("demo_public_key.pem")
    receiver.load_rsa_private_key("demo_private_key.pem")
    encrypted_key, encrypted_data, signature = receiver.load_encrypted_data("demo_encrypted.json")
    print()

    print("Шаг 8: Расшифрование сеансового ключа")
    decrypted_key = receiver.decrypt_session_key(encrypted_key)
    print()

    print("Шаг 9: Расшифрование документа")
    decrypted_document = receiver.decrypt_document(encrypted_data)
    decrypted_text = decrypted_document.decode('utf-8')
    print(f"Расшифрованный документ: '{decrypted_text}'")
    print()

    print("Шаг 10: Проверка цифровой подписи")
    is_valid = receiver.verify_signature(decrypted_text, signature)
    if is_valid:
        print("Документ подлинный и не был изменен.")
    else:
        print("ВНИМАНИЕ! Документ был изменен или подпись недействительна.")

    print("\n=== ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА ===")


if __name__ == "__main__":
    demo()