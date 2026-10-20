"""Tầng lưu trữ. Giao diện trừu tượng + cài đặt SQLite.

Bộ kiểm thử dùng bản lưu trong bộ nhớ để chạy nhanh và không để lại tệp rác.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import KeyPair, Signature


class Repository(ABC):
    @abstractmethod
    def save_key(self, key: KeyPair) -> None: ...

    @abstractmethod
    def get_key(self, key_id: str) -> KeyPair | None: ...

    @abstractmethod
    def save_signature(self, sig: Signature) -> None: ...

    @abstractmethod
    def find_signatures_by_key(self, key_id: str) -> list[Signature]:
        """Dùng cho FR-18: liệt kê artifact đã ký bằng khóa bị thu hồi."""


class SqliteRepository(Repository):
    """Cài đặt trên tệp data/sigtool.db, lược đồ ở data/schema.sql."""

    def __init__(self, db_path: str = "data/sigtool.db") -> None:
        self.db_path = db_path

    def init_schema(self) -> None:
        """Chạy data/schema.sql. TODO(B)."""
        raise NotImplementedError

    def save_key(self, key: KeyPair) -> None:
        raise NotImplementedError  # TODO(B)

    def get_key(self, key_id: str) -> KeyPair | None:
        raise NotImplementedError  # TODO(B)

    def save_signature(self, sig: Signature) -> None:
        raise NotImplementedError  # TODO(B)

    def find_signatures_by_key(self, key_id: str) -> list[Signature]:
        raise NotImplementedError  # TODO(C)


class InMemoryRepository(Repository):
    """Bản giả lập cho kiểm thử. TODO(B)."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._sigs: list[Signature] = []

    def save_key(self, key: KeyPair) -> None:
        self._keys[key.key_id] = key

    def get_key(self, key_id: str) -> KeyPair | None:
        return self._keys.get(key_id)

    def save_signature(self, sig: Signature) -> None:
        self._sigs.append(sig)

    def find_signatures_by_key(self, key_id: str) -> list[Signature]:
        return [s for s in self._sigs if s.key_id == key_id]
