"""
ВЛАСНА РЕАЛІЗАЦІЯ OAEP (Optimal Asymmetric Encryption Padding)
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"
"""
from Crypto.Hash import SHA256
import os

class OAEP:
    """
    Власна реалізація OAEP згідно з PKCS#1 v2.1
    """
    
    @staticmethod
    def mgf1(seed, mask_len, hash_func=SHA256):
        """
        MGF1 (Mask Generation Function) з RFC 2437
        
        Аргументи:
            seed: вхідні дані для генерації маски
            mask_len: потрібна довжина маски в байтах
            hash_func: хеш-функція (за замовчуванням SHA256)
        
        Повертає:
            маску заданої довжини
        """
        h_len = hash_func.digest_size
        mask = b''
        counter = 0
        
        # Генеруємо маску блоками по h_len байт
        while len(mask) < mask_len:
            # Конвертуємо counter в 4 байти (big-endian)
            c = counter.to_bytes(4, 'big')
            # Додаємо хеш від seed + counter
            mask += hash_func.new(seed + c).digest()
            counter += 1
        
        # Повертаємо тільки потрібну довжину
        return mask[:mask_len]
    
    @staticmethod
    def pad(message, key_size, hash_func=SHA256, label=b''):
        """
        OAEP padding згідно з PKCS#1 v2.1
        
        Аргументи:
            message: повідомлення для паддінгу (bytes)
            key_size: розмір ключа RSA в байтах
            hash_func: хеш-функція
            label: мітка (за замовчуванням порожня)
        
        Повертає:
            западдоване повідомлення довжиною key_size байт
        """
        h_len = hash_func.digest_size
        k = key_size
        mLen = len(message)
        
        # Перевірка: повідомлення не повинно бути занадто довгим
        if mLen > k - 2 * h_len - 2:
            raise ValueError("Повідомлення занадто довге")
        
        # 1. Хеш мітки (lHash)
        l_hash = hash_func.new(label).digest()
        
        # 2. Створюємо блок даних DB = lHash || PS || 0x01 || M
        #    PS (padding string) - нулі потрібної довжини
        ps_len = k - mLen - 2 * h_len - 2
        PS = b'\x00' * ps_len
        DB = l_hash + PS + b'\x01' + message
        
        # 3. Генеруємо випадкове число seed довжиною h_len
        seed = os.urandom(h_len)
        
        # 4. dbMask = MGF(seed, k - h_len - 1)
        dbMask = OAEP.mgf1(seed, k - h_len - 1, hash_func)
        
        # 5. maskedDB = DB XOR dbMask
        maskedDB = bytes([a ^ b for a, b in zip(DB, dbMask)])
        
        # 6. seedMask = MGF(maskedDB, h_len)
        seedMask = OAEP.mgf1(maskedDB, h_len, hash_func)
        
        # 7. maskedSeed = seed XOR seedMask
        maskedSeed = bytes([a ^ b for a, b in zip(seed, seedMask)])
        
        # 8. EM = 0x00 || maskedSeed || maskedDB
        EM = b'\x00' + maskedSeed + maskedDB
        
        return EM
    
    @staticmethod
    def unpad(em, key_size, hash_func=SHA256, label=b''):
        """
        Видалення OAEP padding та перевірка цілісності
        
        Аргументи:
            em: западдоване повідомлення
            key_size: розмір ключа RSA в байтах
            hash_func: хеш-функція
            label: мітка
        
        Повертає:
            оригінальне повідомлення
        
        Викидає:
            ValueError: якщо padding некоректний або дані пошкоджено
        """
        h_len = hash_func.digest_size
        k = key_size
        
        # Перевірка довжини
        if len(em) != k:
            raise ValueError("Неправильна довжина блоку")
        
        if k < 2 * h_len + 2:
            raise ValueError("Ключ занадто малий для OAEP")
        
        # 1. Розділяємо EM
        maskedSeed = em[1:h_len + 1]
        maskedDB = em[h_len + 1:]
        
        # 2. seedMask = MGF(maskedDB, h_len)
        seedMask = OAEP.mgf1(maskedDB, h_len, hash_func)
        
        # 3. seed = maskedSeed XOR seedMask
        seed = bytes([a ^ b for a, b in zip(maskedSeed, seedMask)])
        
        # 4. dbMask = MGF(seed, k - h_len - 1)
        dbMask = OAEP.mgf1(seed, k - h_len - 1, hash_func)
        
        # 5. DB = maskedDB XOR dbMask
        DB = bytes([a ^ b for a, b in zip(maskedDB, dbMask)])
        
        # 6. Перевіряємо структуру
        l_hash = hash_func.new(label).digest()
        
        # Отримуємо lHash з DB
        db_lhash = DB[:h_len]
        if db_lhash != l_hash:
            raise ValueError("Неправильний хеш мітки")
        
        # Шукаємо 0x01 після PS (всі нулі)
        rest = DB[h_len:]
        
        # Знаходимо перший ненульовий байт (повинен бути 0x01)
        sep_pos = -1
        for i, byte in enumerate(rest):
            if byte != 0:
                if byte == 0x01:
                    sep_pos = i
                break
        
        if sep_pos == -1:
            raise ValueError("Неправильний формат padding: не знайдено 0x01")
        
        # Перевіряємо, що всі байти до sep_pos - нулі
        if not all(b == 0 for b in rest[:sep_pos]):
            raise ValueError("PS повинен складатися з нулів")
        
        # Повідомлення починається після 0x01
        message = rest[sep_pos + 1:]
        
        return message
    
    @staticmethod
    def debug_pad(message, key_size):
        """
        Демонстраційна версія з детальним виведенням для розуміння OAEP
        """
        print("\n" + "=" * 60)
        print("ДЕМОНСТРАЦІЯ OAEP PADDING")
        print("=" * 60)
        
        h_len = SHA256.digest_size
        k = key_size
        mLen = len(message)
        
        print(f"Повідомлення: '{message.decode()}' ({mLen} байт)")
        print(f"Розмір ключа: {k} байт")
        print(f"Розмір хешу: {h_len} байт")
        
        # 1. Хеш мітки
        l_hash = SHA256.new(b'').digest()
        print(f"\n1. lHash (хеш порожньої мітки): {l_hash.hex()[:20]}...")
        
        # 2. Створюємо DB
        ps_len = k - mLen - 2 * h_len - 2
        PS = b'\x00' * ps_len
        DB = l_hash + PS + b'\x01' + message
        print(f"2. DB створено: {len(DB)} байт")
        print(f"   - lHash: {h_len} байт")
        print(f"   - PS: {ps_len} байт нулів")
        print(f"   - 0x01: 1 байт")
        print(f"   - M: {mLen} байт")
        
        # 3. Генеруємо seed
        seed = os.urandom(h_len)
        print(f"3. seed (випадковий): {seed.hex()[:20]}...")
        
        # 4. dbMask
        dbMask = OAEP.mgf1(seed, k - h_len - 1, SHA256)
        print(f"4. dbMask створено: {len(dbMask)} байт")
        
        # 5. maskedDB
        maskedDB = bytes([a ^ b for a, b in zip(DB, dbMask)])
        print(f"5. maskedDB = DB XOR dbMask")
        
        # 6. seedMask
        seedMask = OAEP.mgf1(maskedDB, h_len, SHA256)
        print(f"6. seedMask створено: {len(seedMask)} байт")
        
        # 7. maskedSeed
        maskedSeed = bytes([a ^ b for a, b in zip(seed, seedMask)])
        print(f"7. maskedSeed = seed XOR seedMask")
        
        # 8. EM
        EM = b'\x00' + maskedSeed + maskedDB
        print(f"8. EM створено: {len(EM)} байт")
        print(f"   - 0x00: 1 байт")
        print(f"   - maskedSeed: {len(maskedSeed)} байт")
        print(f"   - maskedDB: {len(maskedDB)} байт")
        
        return EM