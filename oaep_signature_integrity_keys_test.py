"""
ТЕСТ ВАШЕЙ РЕАЛИЗАЦИИ из utils.py
Проверяет, что ваши функции действительно используют OAEP
"""
import sys
import os

# Добавляем путь к родительской папке
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Импортируем ВАШИ функции из utils.py
from utils import (
    generate_keys, encrypt_message, decrypt_message,
    sign_message, verify_signature, load_keys
)

def test_your_oaep_implementation():
    """
    Тест 1: Проверка что ВАШЕ шифрование использует OAEP
    """
    print("\n" + "=" * 70)
    print("ТЕСТ 1: ВАША РЕАЛИЗАЦИЯ OAEP")
    print("=" * 70)
    
    # Генерируем ключи с помощью ВАШЕЙ функции
    print("\n[1] Генерация ключей (generate_keys)...")
    generate_keys("test_my_oaep")
    priv, pub = load_keys("test_my_oaep")
    
    print(f"    Приватный ключ загружен: {priv.size_in_bits()} бит")
    print(f"    Публичный ключ загружен: {pub.size_in_bits()} бит")
    
    # Тест 1: Вероятностное шифрование
    print("\n[2] Тест вероятностного шифрования...")
    message = "Секретное сообщение"
    
    # Шифруем дважды с ВАШЕЙ функцией
    encrypted1 = encrypt_message(message, pub)
    encrypted2 = encrypt_message(message, pub)
    
    print(f"    Сообщение: '{message}'")
    print(f"    Шифротекст 1: {encrypted1.hex()[:50]}...")
    print(f"    Шифротекст 2: {encrypted2.hex()[:50]}...")
    
    if encrypted1 != encrypted2:
        print("    ✅ РАЗНЫЕ - ВАШ код использует OAEP!")
    else:
        print("    ❌ ОДИНАКОВЫЕ - ВАШ код НЕ использует OAEP!")
    
    # Тест 2: Проверка расшифровки
    print("\n[3] Тест расшифровки...")
    decrypted = decrypt_message(encrypted1, priv)
    print(f"    Расшифровано: '{decrypted}'")
    print(f"    Совпадает с оригиналом: {decrypted == message}")
    
    return encrypted1, priv, pub

def test_your_signature():
    """
    Тест 2: Проверка ВАШЕЙ подписи
    """
    print("\n" + "=" * 70)
    print("ТЕСТ 2: ВАША РЕАЛИЗАЦИЯ ПОДПИСИ")
    print("=" * 70)
    
    # Используем те же ключи
    priv, pub = load_keys("test_my_oaep")
    
    message = "Важное сообщение"
    fake_message = "Другое сообщение"
    
    # ВАША подпись
    print(f"\n[1] Подписание сообщения: '{message}'")
    signature = sign_message(message, priv)
    print(f"    Подпись: {len(signature)} байт")
    
    # Проверка ВАШЕЙ подписью
    print("\n[2] Проверка подписи:")
    valid = verify_signature(message, signature, pub)
    print(f"    Для оригинального сообщения: {valid} ✅")
    
    valid_fake = verify_signature(fake_message, signature, pub)
    print(f"    Для другого сообщения: {valid_fake} ❌")
    
    if valid and not valid_fake:
        print("    ✅ ВАША подпись работает правильно!")

def test_your_integrity_check():
    """
    Тест 3: Проверка целостности (должна обнаружить повреждение)
    """
    print("\n" + "=" * 70)
    print("ТЕСТ 3: ПРОВЕРКА ЦЕЛОСТНОСТИ ВАШЕЙ РЕАЛИЗАЦИИ")
    print("=" * 70)
    
    priv, pub = load_keys("test_my_oaep")
    message = "Тестовое сообщение"
    
    # Шифруем ВАШЕЙ функцией
    encrypted = encrypt_message(message, pub)
    print(f"\n[1] Зашифровано: {len(encrypted)} байт")
    
    # Повреждаем шифротекст
    corrupted = bytearray(encrypted)
    corrupted[10] ^= 0xFF  # Меняем один байт
    corrupted = bytes(corrupted)
    
    print(f"[2] Поврежденный шифротекст создан")
    
    # Пытаемся расшифровать ВАШЕЙ функцией
    print(f"[3] Попытка расшифровки поврежденных данных...")
    try:
        result = decrypt_message(corrupted, priv)
        print(f"    ❌ ОШИБКА: Данные расшифровались! Результат: '{result}'")
        print("    ⚠️  Это значит, что ВАША реализация не проверяет целостность!")
    except Exception as e:
        print(f"    ✅ УСПЕХ: Получена ошибка: {e}")
        print("    Это значит, что OAEP обнаружил повреждение!")

def test_different_keys():
    """
    Тест 4: Разные ключи не должны работать друг с другом
    """
    print("\n" + "=" * 70)
    print("ТЕСТ 4: РАЗНЫЕ КЛЮЧИ")
    print("=" * 70)
    
    # Создаем вторую пару ключей
    generate_keys("test_other")
    priv_other, pub_other = load_keys("test_other")
    priv, pub = load_keys("test_my_oaep")
    
    message = "Секретное сообщение"
    
    # Шифруем первым ключом
    encrypted = encrypt_message(message, pub)
    print(f"\n[1] Зашифровано ключом #1")
    
    # Пытаемся расшифровать вторым ключом
    print(f"[2] Попытка расшифровки ключом #2...")
    try:
        result = decrypt_message(encrypted, priv_other)
        print(f"    ❌ ОШИБКА: Данные расшифровались чужим ключом!")
    except Exception as e:
        print(f"    ✅ УСПЕХ: Ошибка при расшифровке чужим ключом: {e}")

def run_all_tests():
    """
    Запуск всех тестов
    """
    print("\n" + "=" * 70)
    print("        ТЕСТИРОВАНИЕ ВАШЕЙ РЕАЛИЗАЦИИ")
    print("=" * 70)
    print("\nПроверяем функции из utils.py:")
    print("  • encrypt_message()")
    print("  • decrypt_message()") 
    print("  • sign_message()")
    print("  • verify_signature()")
    
    # Очистка старых ключей
    import shutil
    if os.path.exists("keys"):
        print("\n[0] Очистка старых ключей...")
        try:
            shutil.rmtree("keys")
            os.makedirs("keys")
            print("    ✅ Ключи удалены")
        except:
            pass
    
    # Запуск тестов
    encrypted, priv, pub = test_your_oaep_implementation()
    test_your_signature()
    test_your_integrity_check()
    test_different_keys()
    
    print("\n" + "=" * 70)
    print("        ИТОГОВЫЙ ВЕРДИКТ")
    print("=" * 70)
    print("""
✅ ЕСЛИ ВСЕ ТЕСТЫ ПРОШЛИ:
   • Ваш код правильно использует OAEP
   • Шифрование вероятностное
   • Подписи работают
   • Целостность проверяется
   • Ключи изолированы

❌ ЕСЛИ КАКОЙ-ТО ТЕСТ НЕ ПРОШЕЛ:
   • Проверьте реализацию в utils.py
   • Убедитесь что используете PKCS1_OAEP
   • Проверьте обработку ошибок
    """)

if __name__ == "__main__":
    run_all_tests()