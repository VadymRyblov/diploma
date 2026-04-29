"""
Обгортка BLAKE3 для сумісності з інтерфейсом PyCryptodome
Для дипломної роботи: "Розробка застосунку з використанням RSA, OAEP та CRT"

Встановлення: pip install blake3
"""
import blake3 as _blake3


class _BLAKE3HashObj:
    """Об'єкт хешу — імітує поведінку PyCryptodome Hash-об'єктів"""

    def __init__(self, data: bytes):
        self._hash = _blake3.blake3(data)

    def digest(self) -> bytes:
        return self._hash.digest()


class BLAKE3Wrapper:
    """
    Обгортка BLAKE3 для сумісності з інтерфейсом PyCryptodome.

    Використовується замість SHA256 у OAEP:
        hash_func.digest_size  → 32 (байти)
        hash_func.new(data)    → об'єкт з методом .digest()
    """

    digest_size: int = 32  # 256 бит, як у SHA-256

    @staticmethod
    def new(data: bytes) -> _BLAKE3HashObj:
        return _BLAKE3HashObj(data)
