"""
Бенчмарк: ВЛАСНИЙ OAEP (BLAKE3 + покращений MGF1) vs СТАНДАРТНИЙ (SHA-256)
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"

Що порівнюємо:
  1. MGF1 окремо     — BLAKE3 vs SHA-256, O(n) vs O(n²)
  2. OAEP pad        — BLAKE3 vs SHA-256
  3. OAEP unpad      — BLAKE3 vs SHA-256
  4. Повний цикл RSA — encrypt + decrypt, RSA-2048
  5. Масштабування   — RSA-1024 / 2048 / 4096
  6. Коректність     — перевірка pad/unpad
"""

import time
import statistics
import os
import unittest

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes

from oaep import OAEP
from blake3_wrapper import BLAKE3Wrapper


# ───────────────────────────────────────────────────────────────────────────
#  Стандартна реалізація MGF1 із SHA-256 — для порівняння
# ───────────────────────────────────────────────────────────────────────────

def mgf1_sha256_original(seed: bytes, mask_len: int) -> bytes:
    """
    Оригінальна MGF1 з SHA-256 та O(n²) конкатенацією bytes +=.
    Відтворює код, який був у проекті до оптимізації.
    """
    h_len = SHA256.digest_size
    mask = b""
    counter = 0
    while len(mask) < mask_len:
        c = counter.to_bytes(4, "big")
        mask += SHA256.new(seed + c).digest()  # O(n²) — кожна += копіює весь буфер
        counter += 1
    return mask[:mask_len]


def oaep_pad_sha256(message: bytes, key_size: int) -> bytes:
    """OAEP pad з SHA-256 (стандартна реалізація)."""
    return OAEP.pad(message, key_size, hash_func=SHA256)


def oaep_unpad_sha256(em: bytes, key_size: int) -> bytes:
    """OAEP unpad з SHA-256 (стандартна реалізація)."""
    return OAEP.unpad(em, key_size, hash_func=SHA256)


# ───────────────────────────────────────────────────────────────────────────
#  Допоміжні функції
# ───────────────────────────────────────────────────────────────────────────

def measure(fn, *args, iterations: int = 200) -> dict:
    """
    Виконує fn(*args) задану кількість разів.
    Повертає словник зі статистикою (секунди).
    """
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn(*args)
        times.append(time.perf_counter() - t0)

    return {
        "mean":   statistics.mean(times),
        "median": statistics.median(times),
        "stdev":  statistics.stdev(times),
        "min":    min(times),
        "max":    max(times),
        "total":  sum(times),
        "n":      iterations,
    }


def speedup(baseline: dict, optimized: dict) -> float:
    """Прискорення: середній час baseline / середній час optimized."""
    return baseline["mean"] / optimized["mean"]


def print_comparison(title: str, baseline: dict, optimized: dict,
                     label_a: str = "SHA-256 (стандарт)",
                     label_b: str = "BLAKE3  (власна)"):
    sp = speedup(baseline, optimized)
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")
    print(f"  {'Метрика':<12} {label_a:>22} {label_b:>22}")
    print(f"  {'─'*56}")
    for key in ("mean", "median", "stdev", "min", "max"):
        a_ms = baseline[key]  * 1000
        b_ms = optimized[key] * 1000
        print(f"  {key:<12} {a_ms:>19.4f} мс {b_ms:>19.4f} мс")
    print(f"  {'─'*56}")
    print(f"  Прискорення : {sp:.2f}x  ({'швидше' if sp > 1 else 'повільніше'})")
    return sp


# ───────────────────────────────────────────────────────────────────────────
#  Тести
# ───────────────────────────────────────────────────────────────────────────

class TestOAEPBenchmark(unittest.TestCase):
    """
    Бенчмарк-тести OAEP.

    Кожен тест:
      1. Вимірює обидві реалізації.
      2. Виводить порівняльну таблицю.
      3. Перевіряє (assert), що власна реалізація не повільніша за стандартну.
         Допуск 10 % (коефіцієнт 0.9) — щоб тест не падав через шум ОС.
    """

    KEY_SIZE_BYTES = 256   # RSA-2048
    ITERATIONS     = 300
    SEED           = os.urandom(32)
    MESSAGE        = b"Benchmark test message for OAEP diploma thesis 2024"

    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 60)
        print("  БЕНЧМАРК: ВЛАСНИЙ OAEP vs СТАНДАРТНИЙ OAEP")
        print("  Розмір ключа : RSA-2048 (256 байт)")
        print(f"  Ітерацій     : {cls.ITERATIONS}")
        print("=" * 60)

        # Генеруємо ключі один раз для всіх тестів
        cls.key_2048 = RSA.generate(2048)
        cls.key_4096 = RSA.generate(4096)

    # ── 1. MGF1 окремо ────────────────────────────────────────────────────

    def test_1_mgf1_speed(self):
        """MGF1: BLAKE3 (O(n) bytearray) vs SHA-256 (O(n²) bytes+=)"""
        mask_len = self.KEY_SIZE_BYTES - 32 - 1  # типова довжина для RSA-2048

        baseline  = measure(mgf1_sha256_original, self.SEED, mask_len,
                            iterations=self.ITERATIONS)
        optimized = measure(OAEP.mgf1, self.SEED, mask_len, BLAKE3Wrapper,
                            iterations=self.ITERATIONS)

        sp = print_comparison(
            "1. MGF1: SHA-256 O(n²)  vs  BLAKE3 O(n)",
            baseline, optimized,
        )
        self.assertGreater(sp, 0.9, "MGF1 з BLAKE3 не повинен бути значно повільнішим")

    # ── 2. OAEP pad ───────────────────────────────────────────────────────

    def test_2_oaep_pad_speed(self):
        """OAEP pad: SHA-256 vs BLAKE3"""
        baseline  = measure(oaep_pad_sha256, self.MESSAGE, self.KEY_SIZE_BYTES,
                            iterations=self.ITERATIONS)
        optimized = measure(OAEP.pad, self.MESSAGE, self.KEY_SIZE_BYTES, BLAKE3Wrapper,
                            iterations=self.ITERATIONS)

        sp = print_comparison("2. OAEP pad: SHA-256  vs  BLAKE3", baseline, optimized)
        self.assertGreater(sp, 0.9, "OAEP pad з BLAKE3 не повинен бути значно повільнішим")

    # ── 3. OAEP unpad ─────────────────────────────────────────────────────

    def test_3_oaep_unpad_speed(self):
        """OAEP unpad: SHA-256 vs BLAKE3"""
        em_sha256 = oaep_pad_sha256(self.MESSAGE, self.KEY_SIZE_BYTES)
        em_blake3 = OAEP.pad(self.MESSAGE, self.KEY_SIZE_BYTES, BLAKE3Wrapper)

        baseline  = measure(oaep_unpad_sha256, em_sha256, self.KEY_SIZE_BYTES,
                            iterations=self.ITERATIONS)
        optimized = measure(OAEP.unpad, em_blake3, self.KEY_SIZE_BYTES, BLAKE3Wrapper,
                            iterations=self.ITERATIONS)

        sp = print_comparison("3. OAEP unpad: SHA-256  vs  BLAKE3", baseline, optimized)
        self.assertGreater(sp, 0.9, "OAEP unpad з BLAKE3 не повинен бути значно повільнішим")

    # ── 4. Повний цикл RSA (encrypt + decrypt) ────────────────────────────

    def test_4_full_rsa_cycle(self):
        """Повний цикл: OAEP pad → RSA encrypt → RSA decrypt → OAEP unpad"""
        key     = self.key_2048
        pub     = key.publickey()
        k       = key.size_in_bytes()
        message = self.MESSAGE

        def full_cycle_sha256():
            padded = OAEP.pad(message, k, SHA256)
            c      = pow(bytes_to_long(padded), pub.e, pub.n)
            raw    = long_to_bytes(pow(c, key.d, key.n), k)
            OAEP.unpad(raw, k, SHA256)

        def full_cycle_blake3():
            padded = OAEP.pad(message, k, BLAKE3Wrapper)
            c      = pow(bytes_to_long(padded), pub.e, pub.n)
            raw    = long_to_bytes(pow(c, key.d, key.n), k)
            OAEP.unpad(raw, k, BLAKE3Wrapper)

        # Менше ітерацій — RSA повільний
        baseline  = measure(full_cycle_sha256, iterations=30)
        optimized = measure(full_cycle_blake3, iterations=30)

        sp = print_comparison(
            "4. Повний цикл RSA-2048: SHA-256  vs  BLAKE3",
            baseline, optimized,
            label_a="SHA-256 повний цикл",
            label_b="BLAKE3  повний цикл",
        )
        self.assertGreater(sp, 0.9, "Повний цикл з BLAKE3 не повинен бути значно повільнішим")

    # ── 5. Масштабування по розміру ключа ─────────────────────────────────

    def test_5_scaling_by_key_size(self):
        """Як прискорення залежить від розміру ключа RSA."""
        print(f"\n{'─'*60}")
        print("  5. Масштабування MGF1 по розміру ключа")
        print(f"  {'Ключ':<12} {'SHA-256 (мс)':>16} {'BLAKE3 (мс)':>16} {'Прискорення':>14}")
        print(f"  {'─'*58}")

        for key_bytes in [128, 256, 512]:   # RSA-1024 / 2048 / 4096
            mask_len  = key_bytes - 32 - 1
            baseline  = measure(mgf1_sha256_original, self.SEED, mask_len, iterations=200)
            optimized = measure(OAEP.mgf1, self.SEED, mask_len, BLAKE3Wrapper, iterations=200)
            sp        = speedup(baseline, optimized)

            print(
                f"  RSA-{key_bytes*8:<6}"
                f"  {baseline['mean']*1000:>12.4f} мс"
                f"  {optimized['mean']*1000:>12.4f} мс"
                f"  {sp:>11.2f}x"
            )
            self.assertGreater(sp, 0.9)

    # ── 6. Коректність (sanity check) ─────────────────────────────────────

    def test_6_correctness(self):
        """Перевіряємо, що BLAKE3-OAEP дійсно розшифровує те, що зашифрував."""
        k = self.KEY_SIZE_BYTES
        for msg in [b"Hello", b"A" * 100, os.urandom(50)]:
            em      = OAEP.pad(msg, k, BLAKE3Wrapper)
            decoded = OAEP.unpad(em, k, BLAKE3Wrapper)
            self.assertEqual(msg, decoded, "BLAKE3 OAEP: повідомлення не збіглося після unpad")

        print("\n  6. Коректність: ✅ всі повідомлення розшифровані вірно")


# ───────────────────────────────────────────────────────────────────────────
#  Запуск
# ───────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
