"""Danh sách khóa tin cậy có phiên bản, và luân chuyển khóa (FR-15, FR-16)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class TrustEntry:
    key_id: str
    valid_from: datetime
    valid_to: datetime | None = None


@dataclass
class TrustList:
    version: int
    created_at: datetime
    entries: list[TrustEntry]

    def is_trusted(self, key_id: str, moment: datetime) -> bool:
        """Khóa có được tin tại thời điểm ``moment`` không.

        Đây là chỗ giai đoạn chồng lấn phát huy tác dụng: trong khoảng chồng
        lấn, cả khóa cũ lẫn khóa mới đều trả True.

        TODO(C).
        """
        raise NotImplementedError

    @staticmethod
    def load(path: str) -> "TrustList":
        raise NotImplementedError  # TODO(C)

    def save(self, path: str) -> None:
        raise NotImplementedError  # TODO(C)


class KeyRotationService:
    """Luân chuyển khóa với giai đoạn chồng lấn (FR-16)."""

    def __init__(self, overlap_days: int = 14) -> None:
        self.overlap_days = overlap_days

    def rotate(self, old_key_id: str, new_key_id: str, now: datetime) -> TrustList:
        """Phát hành trust list phiên bản mới.

        Khóa cũ giữ hiệu lực thêm ``overlap_days`` ngày để hệ thống chưa kịp
        cập nhật vẫn xác minh được.

        TODO(C).
        """
        raise NotImplementedError
