"""Danh sách khóa tin cậy có phiên bản, và luân chuyển khóa (FR-15, FR-16).

Trust list là thứ quyết định khóa nào được tin. Nó quan trọng ngang khóa
riêng: ai thêm được khóa vào đây thì người đó thắng, không cần phá mật mã.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

ISO = "%Y-%m-%dT%H:%M:%S.%f"


def _dt(v: str | None) -> datetime | None:
    return datetime.strptime(v, ISO) if v else None


def _s(v: datetime | None) -> str | None:
    return v.strftime(ISO) if v else None


@dataclass
class TrustEntry:
    """Một khóa được tin, kèm khoảng thời gian hiệu lực."""

    key_id: str
    valid_from: datetime
    valid_to: datetime | None = None

    def covers(self, moment: datetime) -> bool:
        if moment < self.valid_from:
            return False
        if self.valid_to is not None and moment > self.valid_to:
            return False
        return True


@dataclass
class TrustList:
    """Danh sách khóa tin cậy tại một phiên bản cụ thể."""

    version: int
    created_at: datetime
    entries: list[TrustEntry]
    note: str = ""

    def is_trusted(self, key_id: str, moment: datetime) -> bool:
        """Khóa có được tin tại thời điểm ``moment`` không.

        Đây là chỗ giai đoạn chồng lấn phát huy tác dụng: trong khoảng chồng
        lấn, cả khóa cũ lẫn khóa mới đều trả True, nên hệ thống chưa kịp cập
        nhật vẫn xác minh được chữ ký cũ.
        """
        return any(e.key_id == key_id and e.covers(moment) for e in self.entries)

    def add(self, entry: TrustEntry) -> None:
        for i, e in enumerate(self.entries):
            if e.key_id == entry.key_id:
                self.entries[i] = entry
                return
        self.entries.append(entry)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "created_at": _s(self.created_at),
            "note": self.note,
            "entries": [
                {
                    "key_id": e.key_id,
                    "valid_from": _s(e.valid_from),
                    "valid_to": _s(e.valid_to),
                }
                for e in sorted(self.entries, key=lambda x: x.key_id)
            ],
        }

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @staticmethod
    def load(path: str | Path) -> "TrustList":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return TrustList(
            version=d["version"],
            created_at=_dt(d["created_at"]),
            note=d.get("note", ""),
            entries=[
                TrustEntry(
                    key_id=e["key_id"],
                    valid_from=_dt(e["valid_from"]),
                    valid_to=_dt(e["valid_to"]),
                )
                for e in d["entries"]
            ],
        )

    @staticmethod
    def latest_in(dir_path: str | Path) -> "TrustList | None":
        """Đọc trust list có số phiên bản cao nhất trong thư mục."""
        files = sorted(Path(dir_path).glob("trust_list_v*.json"))
        if not files:
            return None
        return TrustList.load(max(files, key=lambda p: int(p.stem.split("v")[-1])))


class KeyRotationService:
    """Luân chuyển khóa với giai đoạn chồng lấn (FR-16).

    Mặc định 14 ngày. Giai đoạn này tồn tại vì không phải máy nào cũng cập
    nhật trust list ngay; cắt khóa cũ lập tức sẽ làm mọi chữ ký cũ bị từ chối
    oan trong khi chúng hoàn toàn hợp lệ.
    """

    def __init__(self, keys_dir: str | Path = "keys", overlap_days: int = 14) -> None:
        self.keys_dir = Path(keys_dir)
        self.overlap_days = overlap_days

    def publish_initial(self, key_id: str, now: datetime, note: str = "") -> TrustList:
        """Phát hành trust list phiên bản 1 với một khóa duy nhất."""
        tl = TrustList(
            version=1,
            created_at=now,
            entries=[TrustEntry(key_id=key_id, valid_from=now)],
            note=note or "Phat hanh lan dau",
        )
        tl.save(self.keys_dir / "trust_list_v1.json")
        return tl

    def rotate(self, old_key_id: str, new_key_id: str, now: datetime) -> TrustList:
        """Phát hành trust list phiên bản mới khi luân chuyển khóa.

        Khóa cũ giữ hiệu lực thêm ``overlap_days`` ngày; khóa mới hiệu lực
        ngay. Sau giai đoạn chồng lấn, chữ ký bằng khóa cũ trả về KEY_EXPIRED.
        """
        current = TrustList.latest_in(self.keys_dir)
        version = (current.version + 1) if current else 1
        entries: list[TrustEntry] = []

        if current:
            for e in current.entries:
                if e.key_id == old_key_id:
                    entries.append(
                        TrustEntry(
                            key_id=e.key_id,
                            valid_from=e.valid_from,
                            valid_to=now + timedelta(days=self.overlap_days),
                        )
                    )
                else:
                    entries.append(e)

        entries.append(TrustEntry(key_id=new_key_id, valid_from=now))

        tl = TrustList(
            version=version,
            created_at=now,
            entries=entries,
            note=f"Luan chuyen tu {old_key_id} sang {new_key_id}, "
            f"chong lan {self.overlap_days} ngay",
        )
        tl.save(self.keys_dir / f"trust_list_v{version}.json")
        return tl

    def revoke_in_trust_list(
        self, key_id: str, revoked_at: datetime, now: datetime
    ) -> TrustList:
        """Phát hành trust list mới, cắt hiệu lực khóa bị thu hồi.

        Cắt tại thời điểm NGHI NGỜ BỊ LỘ, không phải hôm nay: mọi chữ ký tạo
        sau mốc đó đều không đáng tin.
        """
        current = TrustList.latest_in(self.keys_dir)
        version = (current.version + 1) if current else 1
        entries = []
        if current:
            for e in current.entries:
                if e.key_id == key_id:
                    entries.append(
                        TrustEntry(
                            key_id=e.key_id,
                            valid_from=e.valid_from,
                            valid_to=revoked_at,
                        )
                    )
                else:
                    entries.append(e)
        tl = TrustList(
            version=version,
            created_at=now,
            entries=entries,
            note=f"Thu hoi khoa {key_id} tu {_s(revoked_at)}",
        )
        tl.save(self.keys_dir / f"trust_list_v{version}.json")
        return tl
