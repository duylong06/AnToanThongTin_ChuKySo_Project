"""Tầng lưu trữ. Giao diện trừu tượng + cài đặt SQLite.

Cơ sở dữ liệu ở đây đóng vai SỔ GHI CHÉP, không phải phần lõi: lõi vẫn thao
tác trên tệp (artifact, chữ ký tách rời, manifest JSON). SQLite chỉ trả lời
những câu hỏi kiểu "khóa này đã ký những gì", vốn rất phiền nếu phải quét
thư mục.

Bộ kiểm thử dùng bản lưu trong bộ nhớ để chạy nhanh và không để lại tệp rác.
"""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path

from .models import Algorithm, KeyPair, Signature

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "data" / "schema.sql"
ISO = "%Y-%m-%dT%H:%M:%S.%f"


def _dt(value: str | None) -> datetime | None:
    return datetime.strptime(value, ISO) if value else None


def _s(value: datetime | None) -> str | None:
    return value.strftime(ISO) if value else None


class Repository(ABC):
    @abstractmethod
    def save_key(self, key: KeyPair) -> None: ...

    @abstractmethod
    def get_key(self, key_id: str) -> KeyPair | None: ...

    @abstractmethod
    def list_keys(self) -> list[KeyPair]: ...

    @abstractmethod
    def set_key_status(self, key_id: str, status: str) -> None: ...

    @abstractmethod
    def save_signature(self, sig: Signature) -> None: ...

    @abstractmethod
    def get_signature(self, signature_id: str) -> Signature | None: ...

    @abstractmethod
    def find_signatures_by_key(self, key_id: str) -> list[Signature]:
        """Dùng cho FR-18: liệt kê artifact đã ký bằng khóa bị thu hồi."""

    @abstractmethod
    def log_verification(
        self,
        signature_id: str,
        result: str,
        reason_code: str,
        verifier: str | None,
        duration_ms: float,
        trust_list_version: int | None = None,
    ) -> None: ...

    @abstractmethod
    def save_revocation(
        self, key_id: str, reason: str, revoked_at: datetime, affected: int
    ) -> None: ...

    @abstractmethod
    def get_revocation(self, key_id: str) -> datetime | None:
        """Thời điểm khóa bị thu hồi, hoặc None nếu chưa bị thu hồi."""


class SqliteRepository(Repository):
    """Cài đặt trên tệp ``data/sigtool.db``, lược đồ ở ``data/schema.sql``."""

    def __init__(self, db_path: str = "data/sigtool.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        return con

    def init_schema(self, schema_path: str | Path | None = None) -> None:
        """Tạo toàn bộ bảng. Chạy lại nhiều lần không sao vì dùng IF NOT EXISTS."""
        sql = Path(schema_path or SCHEMA_PATH).read_text(encoding="utf-8")
        with self._conn() as con:
            con.executescript(sql)

    def save_key(self, key: KeyPair) -> None:
        with self._conn() as con:
            con.execute(
                """INSERT OR REPLACE INTO key_pair
                   (key_id, alg, public_key_pem, private_key_path, fingerprint,
                    created_at, expires_at, status, owner)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    key.key_id,
                    key.alg.value,
                    key.public_key_pem,
                    key.private_key_path,
                    key.fingerprint,
                    _s(key.created_at),
                    _s(key.expires_at),
                    key.status,
                    key.owner,
                ),
            )

    @staticmethod
    def _row_to_key(r: sqlite3.Row) -> KeyPair:
        return KeyPair(
            key_id=r["key_id"],
            alg=Algorithm(r["alg"]),
            public_key_pem=r["public_key_pem"],
            private_key_path=r["private_key_path"],
            fingerprint=r["fingerprint"],
            created_at=_dt(r["created_at"]),
            expires_at=_dt(r["expires_at"]),
            status=r["status"],
            owner=r["owner"],
        )

    def get_key(self, key_id: str) -> KeyPair | None:
        with self._conn() as con:
            r = con.execute(
                "SELECT * FROM key_pair WHERE key_id = ?", (key_id,)
            ).fetchone()
        return self._row_to_key(r) if r else None

    def list_keys(self) -> list[KeyPair]:
        with self._conn() as con:
            rows = con.execute("SELECT * FROM key_pair ORDER BY created_at").fetchall()
        return [self._row_to_key(r) for r in rows]

    def set_key_status(self, key_id: str, status: str) -> None:
        with self._conn() as con:
            con.execute(
                "UPDATE key_pair SET status = ? WHERE key_id = ?", (status, key_id)
            )

    def save_signature(self, sig: Signature) -> None:
        with self._conn() as con:
            con.execute(
                """INSERT OR REPLACE INTO signature
                   (signature_id, target_id, target_kind, key_id, alg,
                    sig_path, sig_size_bytes, signed_at, timestamp_token)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    sig.signature_id,
                    sig.target_id,
                    sig.target_kind,
                    sig.key_id,
                    sig.alg.value,
                    sig.sig_path,
                    sig.sig_size_bytes,
                    _s(sig.signed_at),
                    sig.timestamp_token,
                ),
            )

    @staticmethod
    def _row_to_sig(r: sqlite3.Row) -> Signature:
        return Signature(
            signature_id=r["signature_id"],
            target_id=r["target_id"],
            target_kind=r["target_kind"],
            key_id=r["key_id"],
            alg=Algorithm(r["alg"]),
            sig_path=r["sig_path"],
            sig_size_bytes=r["sig_size_bytes"],
            signed_at=_dt(r["signed_at"]),
            timestamp_token=r["timestamp_token"],
        )

    def get_signature(self, signature_id: str) -> Signature | None:
        with self._conn() as con:
            r = con.execute(
                "SELECT * FROM signature WHERE signature_id = ?", (signature_id,)
            ).fetchone()
        return self._row_to_sig(r) if r else None

    def find_signatures_by_key(self, key_id: str) -> list[Signature]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT * FROM signature WHERE key_id = ? ORDER BY signed_at",
                (key_id,),
            ).fetchall()
        return [self._row_to_sig(r) for r in rows]

    def log_verification(
        self,
        signature_id: str,
        result: str,
        reason_code: str,
        verifier: str | None,
        duration_ms: float,
        trust_list_version: int | None = None,
    ) -> None:
        with self._conn() as con:
            con.execute(
                """INSERT INTO verification_log
                   (signature_id, verified_at, result, reason_code,
                    trust_list_version, verifier, duration_ms)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    signature_id,
                    _s(datetime.now()),
                    result,
                    reason_code,
                    trust_list_version,
                    verifier,
                    duration_ms,
                ),
            )

    def save_revocation(
        self, key_id: str, reason: str, revoked_at: datetime, affected: int
    ) -> None:
        with self._conn() as con:
            con.execute(
                """INSERT OR REPLACE INTO revocation
                   (key_id, revoked_at, reason, action_taken, affected_signatures)
                   VALUES (?,?,?,?,?)""",
                (key_id, _s(revoked_at), reason, "canh bao", affected),
            )

    def get_revocation(self, key_id: str) -> datetime | None:
        with self._conn() as con:
            r = con.execute(
                "SELECT revoked_at FROM revocation WHERE key_id = ?", (key_id,)
            ).fetchone()
        return _dt(r["revoked_at"]) if r else None


class InMemoryRepository(Repository):
    """Bản giả lập cho kiểm thử: cùng giao diện, không đụng đĩa."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._sigs: dict[str, Signature] = {}
        self._revocations: dict[str, datetime] = {}
        self.logs: list[dict] = []

    def save_key(self, key: KeyPair) -> None:
        self._keys[key.key_id] = key

    def get_key(self, key_id: str) -> KeyPair | None:
        return self._keys.get(key_id)

    def list_keys(self) -> list[KeyPair]:
        return list(self._keys.values())

    def set_key_status(self, key_id: str, status: str) -> None:
        if key_id in self._keys:
            self._keys[key_id].status = status

    def save_signature(self, sig: Signature) -> None:
        self._sigs[sig.signature_id] = sig

    def get_signature(self, signature_id: str) -> Signature | None:
        return self._sigs.get(signature_id)

    def find_signatures_by_key(self, key_id: str) -> list[Signature]:
        return [s for s in self._sigs.values() if s.key_id == key_id]

    def log_verification(
        self,
        signature_id: str,
        result: str,
        reason_code: str,
        verifier: str | None,
        duration_ms: float,
        trust_list_version: int | None = None,
    ) -> None:
        self.logs.append(
            {
                "signature_id": signature_id,
                "result": result,
                "reason_code": reason_code,
                "verifier": verifier,
                "duration_ms": duration_ms,
            }
        )

    def save_revocation(
        self, key_id: str, reason: str, revoked_at: datetime, affected: int
    ) -> None:
        self._revocations[key_id] = revoked_at

    def get_revocation(self, key_id: str) -> datetime | None:
        return self._revocations.get(key_id)
