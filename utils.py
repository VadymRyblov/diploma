"""
Утиліти для захищеного месенджера - ВЛАСНІ РЕАЛІЗАЦІЇ OAEP та CRT
"""
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import os
import json
from datetime import datetime
from oaep import OAEP        # ВАША власна реалізація OAEP
from crt_implementation import CRT  # ВАША власна реалізація CRT

KEY_FOLDER = "keys"
LOG_FILE = os.path.join("logs", "chat.log")
USE_CRT = True  # Використовувати CRT оптимізацію

def ensure_folders():
    """Створює необхідні папки"""
    for folder in [KEY_FOLDER, "logs"]:
        if not os.path.exists(folder):
            os.makedirs(folder)

def write_log(source: str, message: str, level="INFO"):
    """Запис в лог"""
    ensure_folders()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{source}] [{level}] {message}\n"
    print(log_line, end='')
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def generate_keys(name, key_size=2048):
    """Генерація пари ключів RSA (БІБЛІОТЕЧНИЙ RSA)"""
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
    
    write_log("KEYS", f"Згенеровано ключі для '{name}'")

def load_keys(name):
    """Завантаження ключів з файлів"""
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
    """Серіалізація ключа в рядок"""
    return key.export_key('PEM').decode('ascii')

def deserialize_key(key_str):
    """Десеріалізація ключа з рядка"""
    return RSA.import_key(key_str.encode('ascii'))

def encrypt_message(message: str, public_key: RSA.RsaKey) -> bytes:
    """
    Шифрування з ВАШИМ OAEP та БІБЛІОТЕЧНИМ RSA
    
    1. ВАШ OAEP padding
    2. БАЗОВА RSA операція (бібліотечна)
    """
    # 1. ВАШ OAEP padding
    key_size = public_key.size_in_bytes()
    message_bytes = message.encode('utf-8')
    padded = OAEP.pad(message_bytes, key_size)
    
    write_log("OAEP", f"ВЛАСНИЙ OAEP pad: {len(message_bytes)} -> {len(padded)} байт", "INFO")
    
    # 2. БАЗОВА RSA операція (бібліотечна)
    m = bytes_to_long(padded)
    c = pow(m, public_key.e, public_key.n)
    ciphertext = long_to_bytes(c, key_size)
    
    return ciphertext

def decrypt_message(encrypted: bytes, private_key: RSA.RsaKey) -> str:
    """
    Розшифровка з власних CRT та OAEP
    
    1. Власна CRT оптимізація (або стандартна RSA)
    2. Власна OAEP перевірка та видалення padding
    """
    key_size = private_key.size_in_bytes()
    c = bytes_to_long(encrypted)
    
    # 1. ВАША CRT оптимізація для RSA
    if USE_CRT and hasattr(private_key, 'p') and private_key.p is not None:
        # Використовуємо ВАШ CRT
        m_int = CRT.decrypt(c, private_key)
        write_log("CRT", "Використано CRT реалізацію для розшифровки", "INFO")
    else:
        # Стандартне піднесення до степеня (якщо немає CRT параметрів)
        m_int = pow(c, private_key.d, private_key.n)
        write_log("RSA", "Використано стандартну RSA операцію", "INFO")
    
    # Отримуємо "сирі" дані після RSA
    raw = long_to_bytes(m_int, key_size)
    
    # 2. ВАШ OAEP перевірка та видалення padding
    try:
        message_bytes = OAEP.unpad(raw, key_size)
        write_log("OAEP", "OAEP успішно перевірив цілісність", "INFO")
        return message_bytes.decode('utf-8')
    except Exception as e:
        write_log("OAEP", f"ПОМИЛКА OAEP: {e}", "ERROR")
        raise ValueError(f"Помилка розшифровки: цілісність даних порушено або невірний ключ")

def get_timestamp():
    """Отримання часової мітки"""
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")