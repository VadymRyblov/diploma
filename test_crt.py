"""
Тест CRT оптимизации для расшифровки
"""
from utils import generate_keys, load_keys, encrypt_message, decrypt_message, sign_message, verify_signature
from crt_implementation import OAEP_CRT
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import time

def test_crt_decryption():
    """Тест CRT расшифровки"""
    print("=" * 60)
    print("ТЕСТ CRT ОПТИМИЗАЦИИ ДЛЯ РАСШИФРОВКИ")
    print("=" * 60)
    
    # Генерируем ключи
    print("\n1. Генерация ключей...")
    generate_keys("test")
    priv, pub = load_keys("test")
    
    print(f"   Размер ключа: {priv.size_in_bits()} бит")
    print(f"   CRT параметры: p={priv.p.bit_length()} бит, q={priv.q.bit_length()} бит")
    
    # Тестовое сообщение
    message = "Привет, мир! Это тестовое сообщение для проверки CRT."
    print(f"\n2. Исходное сообщение: '{message}'")
    
    # Шифруем
    print("\n3. Шифрование...")
    encrypted = encrypt_message(message, pub)
    print(f"   Зашифровано: {len(encrypted)} байт")
    
    # Расшифровка с CRT
    print("\n4. Расшифровка с CRT...")
    start = time.time()
    try:
        decrypted = decrypt_message(encrypted, priv)
        crt_time = time.time() - start
        print(f"   ✓ УСПЕШНО! Время: {crt_time*1000:.2f} мс")
        print(f"   Расшифровано: '{decrypted}'")
        assert decrypted == message, "Сообщения не совпадают!"
    except Exception as e:
        print(f"   ✗ ОШИБКА: {e}")
    
    # Тест подписи
    print("\n5. Подписание с CRT...")
    start = time.time()
    signature = sign_message(message, priv)
    sign_time = time.time() - start
    print(f"   Подпись создана: {len(signature)} байт за {sign_time*1000:.2f} мс")
    
    # Проверка подписи
    valid = verify_signature(message, signature, pub)
    print(f"   Подпись верна: {valid}")
    
    print("\n" + "=" * 60)
    print("ТЕСТ ЗАВЕРШЕН")
    print("=" * 60)

if __name__ == "__main__":
    test_crt_decryption()