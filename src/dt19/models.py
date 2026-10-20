"""Lớp miền: kiểu dữ liệu thuần, không phụ thuộc đĩa hay cơ sở dữ liệu.

Tầng này cố ý không biết gì về SQLite, về thư viện mật mã hay về dòng lệnh.
Nhờ vậy bộ kiểm thử dựng được đối tượng ở đây mà không cần chuẩn bị gì.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class Algorithm(str, Enum):
    """Ba thuật toán chữ ký đề tài yêu cầu so sánh."""

    RSA_PSS_2048 = "rsa_pss_2048"
    RSA_PSS_3072 = "rsa_pss_3072"
    ECDSA_P256 = "ecdsa_p256"
    ED25519 = "ed25519"


class ReasonCode(str, Enum):
    """Mã lý do trả về khi xác minh (FR-11).

    Có mã riêng cho từng loại sai lệch là yêu cầu bắt buộc: người dùng cần
    biết "sai ở đâu", không chỉ biết "sai".
    """

    OK = "OK"
    SIG_INVALID = "SIG_INVALID"
    CONTENT_MODIFIED = "CONTENT_MODIFIED"
    METADATA_MODIFIED = "METADATA_MODIFIED"
    KEY_UNKNOWN = "KEY_UNKNOWN"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_EXPIRED = "KEY_EXPIRED"
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    MANIFEST_VERSION_MISMATCH = "MANIFEST_VERSION_MISMATCH"


MESSAGES_VI: dict[ReasonCode, str] = {
    ReasonCode.OK: "Xác minh thành công.",
    ReasonCode.SIG_INVALID: "Chữ ký không khớp với nội dung tệp.",
    ReasonCode.CONTENT_MODIFIED: "Nội dung tệp đã bị sửa so với lúc ký.",
    ReasonCode.METADATA_MODIFIED: "Metadata được bảo vệ đã bị sửa.",
    ReasonCode.KEY_UNKNOWN: "Khóa ký không nằm trong danh sách tin cậy.",
    ReasonCode.KEY_REVOKED: "Khóa ký đã bị thu hồi trước thời điểm ký.",
    ReasonCode.KEY_EXPIRED: "Khóa ký đã hết hạn tại thời điểm ký.",
    ReasonCode.TIMESTAMP_INVALID: "Dấu thời gian không kiểm chứng được.",
    ReasonCode.MANIFEST_VERSION_MISMATCH: "Phiên bản manifest không khớp.",
}


def sha256_file(path: str | Path) -> str:
    """Mã băm SHA-256 của một tệp, đọc theo khối để không nuốt hết bộ nhớ."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Mã băm SHA-256 của một chuỗi byte."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class KeyPair:
    """Một cặp khóa đã đăng ký.

    Khóa riêng chỉ lưu ĐƯỜNG DẪN, không bao giờ lưu nội dung vào cơ sở dữ liệu
    hay vào log. Đây là yêu cầu NFR-04 và NFR-06.
    """

    key_id: str
    alg: Algorithm
    public_key_pem: str
    private_key_path: str
    fingerprint: str
    created_at: datetime
    expires_at: datetime | None = None
    status: str = "active"
    owner: str | None = None

    def is_valid_at(self, moment: datetime) -> bool:
        """Khóa còn hiệu lực tại thời điểm ``moment`` hay không.

        Khóa đã thu hồi thì không bao giờ hợp lệ, kể cả với thời điểm trong
        quá khứ: việc phân loại chữ ký cũ do RevocationService đảm nhiệm,
        không phải hàm này.
        """
        if self.status == "revoked":
            return False
        if moment < self.created_at:
            return False
        if self.expires_at is not None and moment > self.expires_at:
            return False
        return True


@dataclass
class ManifestEntry:
    """Một dòng trong manifest: tệp nào, băm ra sao, lúc lập manifest."""

    artifact_id: str
    path: str
    sha256_at_time: str
    size_at_time: int

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "sha256": self.sha256_at_time,
            "size": self.size_at_time,
        }


@dataclass
class Manifest:
    """Danh sách artifact kèm mã băm, có phiên bản và định danh khóa ký (FR-05).

    Ký manifest thay vì ký từng tệp: một chữ ký bảo vệ cả bộ, và nếu ai đó
    thêm hay bớt một tệp thì manifest không còn khớp.
    """

    manifest_id: str
    version: int
    key_id: str | None = None
    entries: list[ManifestEntry] = field(default_factory=list)

    def add(self, entry: ManifestEntry) -> None:
        """Thêm một mục. Trùng ``artifact_id`` thì ghi đè mục cũ."""
        for i, existing in enumerate(self.entries):
            if existing.artifact_id == entry.artifact_id:
                self.entries[i] = entry
                return
        self.entries.append(entry)

    def add_file(self, path: str | Path, artifact_id: str | None = None) -> ManifestEntry:
        """Băm một tệp trên đĩa rồi thêm vào manifest."""
        p = Path(path)
        entry = ManifestEntry(
            artifact_id=artifact_id or p.name,
            path=p.name,
            sha256_at_time=sha256_file(p),
            size_at_time=p.stat().st_size,
        )
        self.add(entry)
        return entry

    def to_dict(self) -> dict:
        return {
            "manifest_id": self.manifest_id,
            "version": self.version,
            "key_id": self.key_id,
            "entries": [e.to_dict() for e in self.entries],
        }

    def canonical_bytes(self) -> bytes:
        """Chuỗi byte chuẩn hóa dùng để ký.

        Phải ổn định tuyệt đối: cùng nội dung luôn cho cùng chuỗi byte, bất kể
        thứ tự chèn vào dict hay hệ điều hành đang chạy. Nếu không chuẩn hóa,
        hai máy cùng một manifest sẽ cho hai chữ ký khác nhau và xác minh chéo
        sẽ trượt oan.

        Ba biện pháp: sắp xếp mục theo artifact_id, sắp khóa trong JSON, và
        cố định dấu phân cách.
        """
        data = self.to_dict()
        data["entries"] = sorted(data["entries"], key=lambda e: e["artifact_id"])
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @staticmethod
    def load(path: str | Path) -> "Manifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        m = Manifest(
            manifest_id=data["manifest_id"],
            version=data["version"],
            key_id=data.get("key_id"),
        )
        for e in data["entries"]:
            m.add(
                ManifestEntry(
                    artifact_id=e["artifact_id"],
                    path=e["path"],
                    sha256_at_time=e["sha256"],
                    size_at_time=e["size"],
                )
            )
        return m

    def verify_contents(self, root_dir: str | Path) -> tuple[ReasonCode, str | None]:
        """Đối chiếu từng tệp trên đĩa với mã băm ghi trong manifest.

        Phân biệt hai loại sai lệch, vì nguyên nhân và cách xử lý khác nhau:

        - ``CONTENT_MODIFIED``: tệp còn đó nhưng ruột đã khác, hoặc biến mất.
        - ``METADATA_MODIFIED``: ruột vẫn nguyên nhưng tên tệp bị đổi. Phát
          hiện bằng cách tìm trong thư mục xem có tệp nào cùng mã băm không.
          Đây là kiểu tấn công tráo tên: nội dung hợp lệ, nhưng được đặt vào
          vị trí mà người dùng tưởng là thứ khác.

        Trả về mã lý do kèm tên tệp sai lệch, để thông báo nói rõ tệp nào.
        """
        root = Path(root_dir)
        for entry in self.entries:
            target = root / entry.path
            if not target.exists():
                for other in root.glob("*"):
                    if other.is_file() and sha256_file(other) == entry.sha256_at_time:
                        return (
                            ReasonCode.METADATA_MODIFIED,
                            f"{entry.path} bi doi ten thanh {other.name}",
                        )
                return ReasonCode.CONTENT_MODIFIED, f"{entry.path} khong ton tai"
            if sha256_file(target) != entry.sha256_at_time:
                return ReasonCode.CONTENT_MODIFIED, entry.path
        return ReasonCode.OK, None


@dataclass
class Signature:
    """Chữ ký tách rời: không sửa artifact gốc, chữ ký nằm ở tệp riêng (FR-09)."""

    signature_id: str
    target_id: str
    target_kind: str
    key_id: str
    alg: Algorithm
    sig_path: str
    sig_size_bytes: int
    signed_at: datetime
    timestamp_token: str | None = None


@dataclass
class VerificationResult:
    """Kết quả xác minh.

    Trả về cả mã lý do chứ không chỉ True/False (FR-11). Một hàm trả bool
    không ghi nổi nhật ký có ý nghĩa và không giúp người dùng sửa sai.
    """

    passed: bool
    reason: ReasonCode
    duration_ms: float = 0.0
    detail: str | None = None

    @property
    def message_vi(self) -> str:
        base = MESSAGES_VI[self.reason]
        return f"{base} ({self.detail})" if self.detail else base
