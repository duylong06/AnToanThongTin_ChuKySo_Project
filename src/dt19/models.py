"""Lớp miền: kiểu dữ liệu thuần, không phụ thuộc đĩa hay cơ sở dữ liệu."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Algorithm(str, Enum):
    """Ba thuật toán chữ ký đề tài yêu cầu so sánh."""

    RSA_PSS_2048 = "rsa_pss_2048"
    RSA_PSS_3072 = "rsa_pss_3072"
    ECDSA_P256 = "ecdsa_p256"
    ED25519 = "ed25519"


class ReasonCode(str, Enum):
    """Mã lý do trả về khi xác minh (FR-11)."""

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


@dataclass
class KeyPair:
    """Một cặp khóa đã đăng ký. Khóa riêng chỉ lưu đường dẫn, không lưu nội dung."""

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
        """TODO(A): trả True nếu khóa còn hiệu lực tại thời điểm ``moment``."""
        raise NotImplementedError


@dataclass
class ManifestEntry:
    artifact_id: str
    path: str
    sha256_at_time: str
    size_at_time: int


@dataclass
class Manifest:
    """Danh sách artifact kèm mã băm, có phiên bản và định danh khóa ký (FR-05)."""

    manifest_id: str
    version: int
    key_id: str | None = None
    entries: list[ManifestEntry] = field(default_factory=list)

    def add(self, entry: ManifestEntry) -> None:
        """TODO(B): thêm một mục vào manifest."""
        raise NotImplementedError

    def canonical_bytes(self) -> bytes:
        """Chuỗi byte chuẩn hóa dùng để ký.

        Phải ổn định: cùng nội dung luôn cho cùng chuỗi byte, bất kể thứ tự
        khóa trong dict hay hệ điều hành. Gợi ý: JSON với sort_keys=True,
        separators cố định, mã hóa UTF-8.

        TODO(B).
        """
        raise NotImplementedError


@dataclass
class Signature:
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
    """Kết quả xác minh. Trả về cả mã lý do, không chỉ True/False (FR-11)."""

    passed: bool
    reason: ReasonCode
    duration_ms: float = 0.0

    @property
    def message_vi(self) -> str:
        return MESSAGES_VI[self.reason]
