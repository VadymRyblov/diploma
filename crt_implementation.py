"""
Модуль CRT оптимизации для RSA - УПРОЩЕННАЯ ВЕРСИЯ
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes

class CRT:
    """
    Класс с реализацией CRT оптимизации для базовых операций RSA
    """
    
    @staticmethod
    def egcd(a, b):
        """Расширенный алгоритм Евклида"""
        if a == 0:
            return (b, 0, 1)
        g, y, x = CRT.egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
    @staticmethod
    def modinv(a, m):
        """Нахождение обратного элемента"""
        g, x, y = CRT.egcd(a, m)
        if g != 1:
            raise ValueError("Обратный элемент не существует")
        return x % m
    
    @staticmethod
    def decrypt(c, private_key):
        """
        Базовая RSA расшифровка с использованием CRT
        Возвращает число
        """
        n = private_key.n
        d = private_key.d
        p = private_key.p
        q = private_key.q
        
        if p is None or q is None:
            return pow(c, d, n)
        
        # Вычисляем параметры для CRT
        dp = d % (p - 1)
        dq = d % (q - 1)
        q_inv = CRT.modinv(q, p)
        
        # CRT вычисления
        m1 = pow(c % p, dp, p)
        m2 = pow(c % q, dq, q)
        
        # Объединение результатов
        h = (q_inv * (m1 - m2)) % p
        m = m2 + h * q
        
        return m % n
    
    @staticmethod
    def sign(m, private_key):
        """
        Базовая RSA подпись с использованием CRT
        Возвращает число
        """
        # Подпись - это та же операция, что и расшифровка
        return CRT.decrypt(m, private_key)