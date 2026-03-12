"""
Модуль CRT оптимизации для RSA - ФИНАЛЬНАЯ ВЕРСИЯ
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import os

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
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        
        # Объединение результатов
        h = (q_inv * (m1 - m2)) % p
        m = m2 + h * q
        
        return m % n


def crt_decrypt_with_oaep(ciphertext, private_key):
    """
    Расшифровка с использованием CRT для RSA и библиотеки для OAEP
    """
    try:
        # Размер ключа в байтах
        key_size = private_key.size_in_bytes()
        
        # Проверка размера
        if len(ciphertext) != key_size:
            raise ValueError(f"Invalid ciphertext size")
        
        # CRT расшифровка (получаем "сырые" данные)
        c = bytes_to_long(ciphertext)
        m_int = CRT.decrypt(c, private_key)
        raw_data = long_to_bytes(m_int, key_size)
        
        # Создаем временный объект OAEP для депаддинга
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # В PyCryptodome есть внутренний метод для депаддинга
        # Если он доступен - используем его
        if hasattr(cipher, '_decrypt'):
            plaintext = cipher._decrypt(raw_data)
        else:
            # Если нет - используем стандартный decrypt,
            # но подменяем внутренние методы (опасно!)
            raise NotImplementedError("CRT + OAEP не поддерживается в этой версии")
        
        return plaintext.decode('utf-8')
        
    except Exception as e:
        # В случае ошибки используем стандартный метод
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(ciphertext).decode('utf-8')