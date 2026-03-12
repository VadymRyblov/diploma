"""
Утилиты для защищенного мессенджера - ФИНАЛЬНАЯ ВЕРСИЯ
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA1
import os
import json
from datetime import datetime
from crt_implementation import CRT, crt_decrypt_with_oaep
from Crypto.Util.number import bytes_to_long, long_to_bytes

KEY_FOLDER = "keys"
LOG_FILE = os.path.join("logs", "chat.log")
USE_CRT = True  # Включаем CRT оптимизацию

def ensure_folders():
    """Создает необходимые папки"""
    for folder in [KEY_FOLDER, "logs"]:
        if not os.path.exists(folder):
            os.makedirs(folder)

def write_log(source: str, message: str, level="INFO"):
    """Запись в лог"""
    ensure_folders()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{source}] [{level}] {message}\n"
    print(log_line, end='')  # Дублируем в консоль для отладки
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def generate_keys(name, key_size=2048):
    """Генерация пары ключей RSA"""
    ensure_folders()
    priv_path = os.path.join(KEY_FOLDER, f"{name}_private.pem")
    pub_path = os.path.join(KEY_FOLDER, f"{name}_public.pem")
    
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return
    
    key = RSA.generate(key_size)
    with open(priv_path, "wb") as f:
        f.write(key.export_key('PEM'))
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key('PEM'))
    
    write_log("KEYS", f"Сгенерированы ключи для '{name}'")

def load_keys(name):
    """Загрузка ключей из файлов"""
    priv_path = os.path.join(KEY_FOLDER, f"{name}_private.pem")
    pub_path = os.path.join(KEY_FOLDER, f"{name}_public.pem")
    
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        generate_keys(name)
    
    with open(priv_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(pub_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    
    return private_key, public_key

def serialize_key(key):
    """Сериализация ключа в строку"""
    return key.export_key('PEM').decode('ascii')

def deserialize_key(key_str):
    """Десериализация ключа из строки"""
    return RSA.import_key(key_str.encode('ascii'))

def encrypt_message(message: str, public_key: RSA.RsaKey) -> bytes:
    """Шифрование сообщения с использованием RSA-OAEP"""
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted: bytes, private_key: RSA.RsaKey) -> str:
    """
    Расшифровка сообщения с CRT оптимизацией
    """
    if USE_CRT and hasattr(private_key, 'p') and private_key.p is not None:
        try:
            # Используем CRT для расшифровки + библиотеку для OAEP
            plaintext = crt_decrypt_with_oaep(encrypted, private_key)
            write_log("CRT", "Расшифровка с CRT выполнена успешно", "INFO")
            return plaintext
        except Exception as e:
            write_log("CRT", f"Ошибка CRT: {e}, использую стандартный метод", "WARNING")
            # Если CRT не сработал, используем стандартный метод
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            return cipher.decrypt(encrypted).decode()
    else:
        # Стандартная расшифровка без CRT
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(encrypted).decode()

def sign_message(message: str, private_key: RSA.RsaKey) -> bytes:
    """
    Подписание сообщения с использованием CRT оптимизации
    """
    h = SHA256.new(message.encode())
    
    if USE_CRT and hasattr(private_key, 'p') and private_key.p is not None:
        try:
            # Размер ключа в байтах
            k = private_key.size_in_bytes()
            
            # EMSA-PKCS1-v1_5 encoding для SHA256
            digest_info = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20' + h.digest()
            
            # Длина PS (padding string)
            ps_len = k - len(digest_info) - 3
            if ps_len < 8:
                raise ValueError("Key too small")
            
            # Формируем EM
            em = b'\x00\x01' + b'\xff' * ps_len + b'\x00' + digest_info
            
            # Преобразуем EM в число
            em_int = bytes_to_long(em)
            
            # Используем CRT для подписи
            s_int = CRT.decrypt(em_int, private_key)
            
            # Преобразуем обратно в байты
            signature = long_to_bytes(s_int, k)
            
            write_log("CRT", "Подписание с CRT выполнено успешно", "INFO")
            return signature
            
        except Exception as e:
            write_log("CRT", f"Ошибка CRT подписи: {e}, использую стандартный метод", "WARNING")
            return pkcs1_15.new(private_key).sign(h)
    else:
        return pkcs1_15.new(private_key).sign(h)

def verify_signature(message: str, signature: bytes, public_key: RSA.RsaKey) -> bool:
    """Проверка подписи"""
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def get_timestamp():
    """Получение временной метки"""
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")