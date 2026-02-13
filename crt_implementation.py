"""
Модуль CRT оптимизации для RSA
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes

class CRT:
    """
    Класс с реализацией CRT оптимизации
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
    def crt_decrypt(ciphertext: bytes, private_key):
        """
        CRT расшифровка с правильной обработкой
        """
        # Получаем параметры ключа
        n = private_key.n
        d = private_key.d
        p = private_key.p
        q = private_key.q
        
        # Преобразуем ciphertext в число
        c = bytes_to_long(ciphertext)
        
        # Вычисляем параметры для CRT
        dp = d % (p - 1)
        dq = d % (q - 1)
        
        # Находим обратный элемент q^(-1) mod p
        q_inv = CRT.modinv(q, p)
        
        # CRT вычисления
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        
        # Объединение результатов
        h = (q_inv * (m1 - m2)) % p
        m = m2 + h * q
        
        # Преобразуем обратно в байты
        return long_to_bytes(m)
    
    @staticmethod
    def crt_sign(message_int: int, private_key) -> int:
        """
        CRT подписание (возвращает число)
        """
        # Получаем параметры ключа
        n = private_key.n
        d = private_key.d
        p = private_key.p
        q = private_key.q
        
        # Вычисляем параметры для CRT
        dp = d % (p - 1)
        dq = d % (q - 1)
        
        # Находим обратный элемент
        q_inv = CRT.modinv(q, p)
        
        # CRT вычисления
        s1 = pow(message_int % p, dp, p)
        s2 = pow(message_int % q, dq, q)
        
        # Объединение результатов
        h = (q_inv * (s1 - s2)) % p
        s = s2 + h * q
        
        return s % n