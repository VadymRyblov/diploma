"""
Утилиты для защищенного мессенджера - РАБОЧАЯ ВЕРСИЯ
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import json
from datetime import datetime

KEY_FOLDER = "keys"
LOG_FILE = os.path.join("logs", "chat.log")

def ensure_folders():
    """Создает необходимые папки"""
    for folder in [KEY_FOLDER, "logs"]:
        if not os.path.exists(folder):
            os.makedirs(folder)

def write_log(source: str, message: str, level="INFO"):
    """Запись в лог"""
    ensure_folders()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{source}] [{level}] {message}\n")

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
    """Расшифровка сообщения с использованием RSA-OAEP"""
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(encrypted).decode()

def sign_message(message: str, private_key: RSA.RsaKey) -> bytes:
    """Подписание сообщения"""
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

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