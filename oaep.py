"""
ВЛАСНА РЕАЛІЗАЦІЯ OAEP (Optimal Asymmetric Encryption Padding)
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"

Оптимізації порівняно з базовою версією:
  1. Хеш-функція замінена з SHA-256 на BLAKE3 (швидша у 3–10 разів на CPU)
  2. MGF1: O(n) bytearray замість O(n²) конкатенації bytes
  3. MGF1: явна перевірка максимальної довжини маски (RFC 2437)
  4. MGF1: точне обчислення кількості блоків (ceiling division, без зайвого хешування)
  5. MGF1: паралельна версія для великих ключів (≥ 4096 біт)
"""
import os
from concurrent.futures import ThreadPoolExecutor
from blake3_wrapper import BLAKE3Wrapper


class OAEP:
    """
    Власна реалізація OAEP згідно з PKCS#1 v2.1.
    Хеш-функція за замовчуванням — BLAKE3 (замість SHA-256).
    """

    # ------------------------------------------------------------------ #
    #  MGF1                                                                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def mgf1(seed: bytes, mask_len: int, hash_func=BLAKE3Wrapper) -> bytes:
        """
        Покращена MGF1 (Mask Generation Function) — RFC 2437.

        Покращення:
          • bytearray.extend() — O(n) замість bytes += — O(n²)
          • Ceiling division → точна кількість блоків, без зайвого хешування
          • Явна перевірка ліміту довжини маски за стандартом

        Аргументи:
            seed      : вхідні дані для генерації маски
            mask_len  : потрібна довжина маски в байтах
            hash_func : хеш-функція (за замовчуванням BLAKE3)

        Повертає:
            маску заданої довжини (bytes)
        """
        h_len = hash_func.digest_size

        # Перевірка RFC 2437: mask_len ≤ 2^32 * hLen
        if mask_len > (2 ** 32) * h_len:
            raise ValueError(
                f"Запитана маска ({mask_len} байт) перевищує максимум RFC 2437"
            )

        # Точна кількість блоків (ceiling division)
        num_blocks = (mask_len + h_len - 1) // h_len

        # O(n) накопичення через bytearray
        buf = bytearray()
        for counter in range(num_blocks):
            c = counter.to_bytes(4, "big")
            buf.extend(hash_func.new(seed + c).digest())

        return bytes(buf[:mask_len])

    @staticmethod
    def mgf1_parallel(seed: bytes, mask_len: int, hash_func=BLAKE3Wrapper) -> bytes:
        """
        Паралельна MGF1 для великих ключів (≥ 4096 біт).

        Блоки MGF1 незалежні один від одного, тому їх можна хешувати
        одночасно. Для RSA-2048 накладні витрати на потоки перевищують
        виграш — використовуйте звичайний mgf1(). Для RSA-4096 і більше
        паралельна версія дає помітне прискорення.

        Аргументи та повернення — ті самі, що в mgf1().
        """
        h_len = hash_func.digest_size

        if mask_len > (2 ** 32) * h_len:
            raise ValueError(
                f"Запитана маска ({mask_len} байт) перевищує максимум RFC 2437"
            )

        num_blocks = (mask_len + h_len - 1) // h_len

        def compute_block(counter: int) -> bytes:
            c = counter.to_bytes(4, "big")
            return hash_func.new(seed + c).digest()

        with ThreadPoolExecutor() as executor:
            blocks = list(executor.map(compute_block, range(num_blocks)))

        buf = bytearray()
        for block in blocks:
            buf.extend(block)

        return bytes(buf[:mask_len])

    # ------------------------------------------------------------------ #
    #  OAEP Padding / Unpadding                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def pad(
        message: bytes,
        key_size: int,
        hash_func=BLAKE3Wrapper,
        label: bytes = b"",
    ) -> bytes:
        """
        OAEP padding згідно з PKCS#1 v2.1.

        Аргументи:
            message   : повідомлення для паддінгу (bytes)
            key_size  : розмір ключа RSA в байтах
            hash_func : хеш-функція (за замовчуванням BLAKE3)
            label     : мітка (за замовчуванням порожня)

        Повертає:
            западдоване повідомлення довжиною key_size байт

        Викидає:
            ValueError : якщо повідомлення занадто довге
        """
        h_len = hash_func.digest_size
        k = key_size
        m_len = len(message)

        # Перевірка: повідомлення не повинно бути занадто довгим
        if m_len > k - 2 * h_len - 2:
            raise ValueError(
                f"Повідомлення ({m_len} байт) занадто довге для ключа {k} байт з OAEP"
            )

        # 1. lHash = Hash(label)
        l_hash = hash_func.new(label).digest()

        # 2. DB = lHash || PS || 0x01 || M
        ps_len = k - m_len - 2 * h_len - 2
        db = l_hash + b"\x00" * ps_len + b"\x01" + message

        # 3. seed — випадкові байти довжиною h_len
        seed = os.urandom(h_len)

        # 4. dbMask = MGF(seed, k − h_len − 1)
        db_mask = OAEP.mgf1(seed, k - h_len - 1, hash_func)

        # 5. maskedDB = DB ⊕ dbMask
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        # 6. seedMask = MGF(maskedDB, h_len)
        seed_mask = OAEP.mgf1(masked_db, h_len, hash_func)

        # 7. maskedSeed = seed ⊕ seedMask
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

        # 8. EM = 0x00 || maskedSeed || maskedDB
        return b"\x00" + masked_seed + masked_db

    @staticmethod
    def unpad(
        em: bytes,
        key_size: int,
        hash_func=BLAKE3Wrapper,
        label: bytes = b"",
    ) -> bytes:
        """
        Видалення OAEP padding та перевірка цілісності.

        Аргументи:
            em        : западдоване повідомлення
            key_size  : розмір ключа RSA в байтах
            hash_func : хеш-функція (за замовчуванням BLAKE3)
            label     : мітка

        Повертає:
            оригінальне повідомлення

        Викидає:
            ValueError : якщо padding некоректний або дані пошкоджено
        """
        h_len = hash_func.digest_size
        k = key_size

        # Перевірка довжини
        if len(em) != k:
            raise ValueError(f"Неправильна довжина блоку: {len(em)} != {k}")

        if k < 2 * h_len + 2:
            raise ValueError("Ключ занадто малий для OAEP з цією хеш-функцією")

        # 1. Розділяємо EM: 0x00 | maskedSeed | maskedDB
        masked_seed = em[1 : h_len + 1]
        masked_db = em[h_len + 1 :]

        # 2. seedMask = MGF(maskedDB, h_len)
        seed_mask = OAEP.mgf1(masked_db, h_len, hash_func)

        # 3. seed = maskedSeed ⊕ seedMask
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

        # 4. dbMask = MGF(seed, k − h_len − 1)
        db_mask = OAEP.mgf1(seed, k - h_len - 1, hash_func)

        # 5. DB = maskedDB ⊕ dbMask
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        # 6. Перевірка lHash
        l_hash = hash_func.new(label).digest()
        if db[:h_len] != l_hash:
            raise ValueError("Неправильний хеш мітки — дані пошкоджено або невірний ключ")

        # 7. Шукаємо 0x01 після PS (нулів)
        rest = db[h_len:]
        sep_pos = -1
        for i, byte in enumerate(rest):
            if byte != 0:
                if byte == 0x01:
                    sep_pos = i
                break

        if sep_pos == -1:
            raise ValueError("Неправильний формат padding: байт 0x01 не знайдено")

        return rest[sep_pos + 1 :]

    # ------------------------------------------------------------------ #
    #  Debug / Demo                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def debug_pad(message: bytes, key_size: int) -> bytes:
        """
        Демонстраційна версія pad() з детальним виведенням.
        Використовується для пояснення алгоритму в дипломній роботі.
        """
        hash_func = BLAKE3Wrapper
        print("\n" + "=" * 60)
        print("ДЕМОНСТРАЦІЯ OAEP PADDING (BLAKE3 + покращений MGF1)")
        print("=" * 60)

        h_len = hash_func.digest_size
        k = key_size
        m_len = len(message)

        print(f"Повідомлення : '{message.decode()}' ({m_len} байт)")
        print(f"Розмір ключа : {k} байт")
        print(f"Хеш-функція  : BLAKE3 (digest_size = {h_len} байт)")

        l_hash = hash_func.new(b"").digest()
        print(f"\n1. lHash (BLAKE3 порожньої мітки): {l_hash.hex()[:20]}...")

        ps_len = k - m_len - 2 * h_len - 2
        db = l_hash + b"\x00" * ps_len + b"\x01" + message
        print(f"2. DB: {len(db)} байт  (lHash={h_len} | PS={ps_len} | 0x01=1 | M={m_len})")

        seed = os.urandom(h_len)
        print(f"3. seed (випадковий): {seed.hex()[:20]}...")

        db_mask = OAEP.mgf1(seed, k - h_len - 1, hash_func)
        print(f"4. dbMask (покращений MGF1): {len(db_mask)} байт")

        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        print(f"5. maskedDB = DB ⊕ dbMask")

        seed_mask = OAEP.mgf1(masked_db, h_len, hash_func)
        print(f"6. seedMask (покращений MGF1): {len(seed_mask)} байт")

        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        print(f"7. maskedSeed = seed ⊕ seedMask")

        em = b"\x00" + masked_seed + masked_db
        print(f"8. EM: {len(em)} байт  (0x00=1 | maskedSeed={len(masked_seed)} | maskedDB={len(masked_db)})")

        return em
