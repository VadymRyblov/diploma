"""
Модуль CRT оптимізації для RSA - ВЛАСНА РЕАЛІЗАЦІЯ
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time  # Додано для benchmark
import random  # Додано для benchmark

class CRT:
    """
    ВЛАСНА реалізація CRT оптимізації для базових операцій RSA
    
    Китайська теорема про остачі (CRT) дозволяє прискорити
    розшифровку RSA в ~4 рази.
    """
    
    @staticmethod
    def egcd(a, b):
        """
        Розширений алгоритм Евкліда
        Повертає (g, x, y) такі, що a*x + b*y = g = НСД(a, b)
        """
        if a == 0:
            return (b, 0, 1)
        g, y, x = CRT.egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
    @staticmethod
    def modinv(a, m):
        """
        Знаходження оберненого елемента a^(-1) mod m
        Використовує розширений алгоритм Евкліда
        """
        g, x, y = CRT.egcd(a, m)
        if g != 1:
            raise ValueError("Обернений елемент не існує")
        return x % m
    
    @staticmethod
    def decrypt(c, private_key):
        """
        ВЛАСНА реалізація RSA розшифровки з використанням CRT
        
        Аргументи:
            c: зашифроване повідомлення як число
            private_key: об'єкт приватного ключа RSA (з параметрами p, q)
        
        Повертає:
            розшифроване повідомлення як число
        
        Математика:
            Замість обчислення m = c^d mod n (повільно),
            обчислюємо:
                m1 = c^(d mod (p-1)) mod p
                m2 = c^(d mod (q-1)) mod q
                h = q_inv * (m1 - m2) mod p
                m = m2 + h * q
            
            Це працює в ~4 рази швидше!
        """
        n = private_key.n
        d = private_key.d
        p = private_key.p
        q = private_key.q
        
        # Якщо немає CRT параметрів - звичайне піднесення до степеня
        if p is None or q is None:
            return pow(c, d, n)
        
        # Обчислюємо параметри для CRT
        # dp = d mod (p-1)
        dp = d % (p - 1)
        # dq = d mod (q-1)
        dq = d % (q - 1)
        # q_inv = q^(-1) mod p
        q_inv = CRT.modinv(q, p)
        
        # CRT обчислення
        # m1 = c^dp mod p
        m1 = pow(c, dp, p)
        # m2 = c^dq mod q
        m2 = pow(c, dq, q)
        
        # Об'єднання результатів за формулою Гарнера
        # h = q_inv * (m1 - m2) mod p
        h = (q_inv * (m1 - m2)) % p
        # m = m2 + h * q
        m = m2 + h * q
        
        return m % n
    
    @staticmethod
    def benchmark(private_key, iterations=100):
        """
        Порівняння швидкості CRT vs звичайний метод
        """
        print("\n" + "=" * 60)
        print("ТЕСТ ПРОДУКТИВНОСТІ: CRT vs ЗВИЧАЙНИЙ МЕТОД")
        print("=" * 60)
        
        # Генеруємо випадкові числа для тесту
        test_numbers = [random.randint(1, private_key.n - 1) for _ in range(iterations)]
        
        # Тест з CRT
        start = time.time()
        for c in test_numbers:
            CRT.decrypt(c, private_key)
        crt_time = time.time() - start
        
        # Тест без CRT (звичайне піднесення до степеня)
        start = time.time()
        for c in test_numbers:
            pow(c, private_key.d, private_key.n)
        normal_time = time.time() - start
        
        print(f"\nКількість ітерацій: {iterations}")
        print(f"Розмір ключа: {private_key.size_in_bits()} біт")
        print(f"\n📊 РЕЗУЛЬТАТИ:")
        print(f"   Звичайний метод: {normal_time*1000:.2f} мс")
        print(f"   З CRT:           {crt_time*1000:.2f} мс")
        print(f"   Прискорення:     {normal_time/crt_time:.2f}x")
        
        return normal_time / crt_time