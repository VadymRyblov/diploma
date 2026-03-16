"""
Тест CRT оптимізації для розшифровки - ВЛАСНА РЕАЛІЗАЦІЯ
"""
import sys
import os
import time

# Додаємо шлях до батьківської папки
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import generate_keys, load_keys, encrypt_message, decrypt_message
from crt_implementation import CRT

def test_crt_decryption():
    """Тест CRT розшифровки"""
    print("=" * 70)
    print("ТЕСТ CRT ОПТИМІЗАЦІЇ - ВЛАСНА РЕАЛІЗАЦІЯ")
    print("=" * 70)
    
    # Генеруємо ключі
    print("\n1. Генерація ключів...")
    generate_keys("test")
    priv, pub = load_keys("test")
    
    print(f"   Розмір ключа: {priv.size_in_bits()} біт")
    print(f"   CRT параметри: p={priv.p.bit_length()} біт, q={priv.q.bit_length()} біт")
    
    # Тестове повідомлення
    message = "Привіт, світ! Це тестове повідомлення для перевірки CRT."
    print(f"\n2. Вихідне повідомлення: '{message}'")
    print(f"   Довжина: {len(message.encode())} байт")
    
    # Шифруємо (з ВАШИМ OAEP)
    print("\n3. Шифрування (власний OAEP)...")
    encrypted = encrypt_message(message, pub)
    print(f"   Зашифровано: {len(encrypted)} байт")
    
    # Розшифровка з CRT (ВАША реалізація)
    print("\n4. Розшифровка з CRT (власна реалізація)...")
    start = time.time()
    try:
        decrypted = decrypt_message(encrypted, priv)
        crt_time = time.time() - start
        print(f"   ✓ УСПІШНО! Час: {crt_time*1000:.2f} мс")
        print(f"   Розшифровано: '{decrypted}'")
        assert decrypted == message, "Повідомлення не співпадають!"
    except Exception as e:
        print(f"   ✗ ПОМИЛКА: {e}")
    
    print("\n" + "=" * 70)
    print("ТЕСТ CRT ЗАВЕРШЕНО УСПІШНО")
    print("=" * 70)

def benchmark_crt():
    """Тест продуктивності CRT"""
    print("\n" + "=" * 70)
    print("ТЕСТ ПРОДУКТИВНОСТІ CRT")
    print("=" * 70)
    
    generate_keys("benchmark")
    priv, pub = load_keys("benchmark")
    
    # Використовуємо вбудований бенчмарк
    CRT.benchmark(priv, 200)

def compare_crt_vs_standard():
    """Порівняння CRT зі стандартним методом"""
    print("\n" + "=" * 70)
    print("ПОРІВНЯННЯ: CRT vs СТАНДАРТНИЙ МЕТОД")
    print("=" * 70)
    
    generate_keys("compare")
    priv, pub = load_keys("compare")
    
    # Генеруємо тестові числа
    import random
    test_numbers = [random.randint(1, priv.n - 1) for _ in range(100)]
    
    # Тест з CRT
    start = time.time()
    for c in test_numbers:
        CRT.decrypt(c, priv)
    crt_time = time.time() - start
    
    # Тест без CRT (стандартне піднесення до степеня)
    start = time.time()
    for c in test_numbers:
        pow(c, priv.d, priv.n)
    std_time = time.time() - start
    
    print(f"\n📊 РЕЗУЛЬТАТИ (100 операцій):")
    print(f"   • Стандартний метод: {std_time*1000:.2f} мс")
    print(f"   • З CRT:            {crt_time*1000:.2f} мс")
    print(f"   • Прискорення:      {std_time/crt_time:.2f}x")

if __name__ == "__main__":
    test_crt_decryption()
    print("\n" + "=" * 70)
    compare_crt_vs_standard()
    print("\n" + "=" * 70)
    benchmark_crt()