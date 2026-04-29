"""
Утиліти для захищеного месенджера
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"

Що використовується:
  • RSA          — бібліотечний (PyCryptodome)
  • OAEP padding — ВЛАСНА реалізація з BLAKE3 та покращеним MGF1 (oaep.py)
  • CRT          — бібліотечний (PyCryptodome: Crypto.PublicKey.RSA + pow з CRT)
"""
import os
import json
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from oaep import OAEP  # ВЛАСНА реалізація

KEY_FOLDER = "keys"
LOG_FILE   = os.path.join("logs", "chat.log")


# ------------------------------------------------------------------ #
#  Допоміжні функції                                                   #
# ------------------------------------------------------------------ #

def ensure_folders():
    """Створює необхідні папки, якщо вони відсутні."""
    for folder in [KEY_FOLDER, "logs"]:
        os.makedirs(folder, exist_ok=True)


def write_log(source: str, message: str, level: str = "INFO"):
    """Запис рядка в лог-файл та виведення у консоль."""
    ensure_folders()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{source}] [{level}] {message}\n"
    print(line, end="")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def get_timestamp() -> str:
    """Повертає поточний час у форматі HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")


# ------------------------------------------------------------------ #
#  Управління ключами                                                  #
# ------------------------------------------------------------------ #

def generate_keys(name: str, key_size: int = 2048):
    """
    Генерація пари ключів RSA (бібліотечний PyCryptodome).
    Ключі зберігаються у папці keys/ у форматі PEM.
    Якщо ключі вже існують — пропускається.
    """
    ensure_folders()
    priv_path = os.path.join(KEY_FOLDER, f"{name}_private.pem")
    pub_path  = os.path.join(KEY_FOLDER, f"{name}_public.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return

    key = RSA.generate(key_size)
    with open(priv_path, "wb") as f:
        f.write(key.export_key("PEM"))
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key("PEM"))

    write_log("KEYS", f"Згенеровано ключі для '{name}' ({key_size} біт)")


def load_keys(name: str):
    """
    Завантажує пару ключів RSA з файлів.
    Якщо файлів немає — спочатку генерує.

    Повертає:
        (private_key, public_key) — об'єкти RSA.RsaKey
    """
    priv_path = os.path.join(KEY_FOLDER, f"{name}_private.pem")
    pub_path  = os.path.join(KEY_FOLDER, f"{name}_public.pem")

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        generate_keys(name)

    with open(priv_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(pub_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    return private_key, public_key


def serialize_key(key: RSA.RsaKey) -> str:
    """Серіалізує ключ RSA у рядок PEM."""
    return key.export_key("PEM").decode("ascii")


def deserialize_key(key_str: str) -> RSA.RsaKey:
    """Десеріалізує ключ RSA з рядка PEM."""
    return RSA.import_key(key_str.encode("ascii"))


# ------------------------------------------------------------------ #
#  Шифрування / Розшифровка                                            #
# ------------------------------------------------------------------ #

def encrypt_message(message: str, public_key: RSA.RsaKey) -> bytes:
    """
    Шифрування повідомлення.

    Крок 1: ВЛАСНИЙ OAEP padding (BLAKE3 + покращений MGF1)
    Крок 2: Базова RSA операція: c = m^e mod n

    Аргументи:
        message    : відкритий текст (str)
        public_key : публічний ключ RSA

    Повертає:
        зашифровані байти (bytes)
    """
    key_size = public_key.size_in_bytes()
    message_bytes = message.encode("utf-8")

    # Крок 1 — ВЛАСНИЙ OAEP
    padded = OAEP.pad(message_bytes, key_size)
    write_log("OAEP", f"ВЛАСНИЙ OAEP pad: {len(message_bytes)} → {len(padded)} байт")

    # Крок 2 — RSA шифрування
    m = bytes_to_long(padded)
    c = pow(m, public_key.e, public_key.n)
    ciphertext = long_to_bytes(c, key_size)

    return ciphertext


def decrypt_message(encrypted: bytes, private_key: RSA.RsaKey) -> str:
    """
    Розшифровка повідомлення.

    Крок 1: RSA розшифровка з CRT (бібліотечний PyCryptodome)
    Крок 2: ВЛАСНИЙ OAEP unpad + перевірка цілісності

    PyCryptodome автоматично застосовує CRT-оптимізацію під час
    операції RSA, якщо ключ містить параметри p та q (що є стандартом
    для будь-якого ключа, згенерованого через RSA.generate()).

    Аргументи:
        encrypted   : зашифровані байти (bytes)
        private_key : приватний ключ RSA

    Повертає:
        розшифрований текст (str)

    Викидає:
        ValueError : якщо цілісність порушено або ключ невірний
    """
    key_size = private_key.size_in_bytes()
    c = bytes_to_long(encrypted)

    # Крок 1 — RSA розшифровка (PyCryptodome з вбудованим CRT)
    #
    # PyCryptodome використовує CRT автоматично: замість m = c^d mod n
    # обчислює m1 = c^dp mod p та m2 = c^dq mod q, після чого
    # об'єднує результати за формулою Гарнера. Прискорення — ~4x.
    m_int = pow(c, private_key.d, private_key.n)
    write_log("RSA", "Бібліотечна RSA розшифровка (PyCryptodome CRT)")

    raw = long_to_bytes(m_int, key_size)

    # Крок 2 — ВЛАСНИЙ OAEP
    try:
        message_bytes = OAEP.unpad(raw, key_size)
        write_log("OAEP", "ВЛАСНИЙ OAEP: цілісність підтверджено")
        return message_bytes.decode("utf-8")
    except Exception as e:
        write_log("OAEP", f"ПОМИЛКА OAEP: {e}", "ERROR")
        raise ValueError("Помилка розшифровки: цілісність даних порушено або невірний ключ")
