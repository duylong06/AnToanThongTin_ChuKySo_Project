"""Fixture dùng chung cho bộ kiểm thử.

Mọi ca kiểm thử chạy trong thư mục tạm riêng, dùng kho lưu trong bộ nhớ,
nên không để lại tệp rác và chạy lại bao nhiêu lần cũng ra kết quả như nhau.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from dt19.models import Manifest
from dt19.repository import InMemoryRepository
from dt19.services import SigningService, TimestampService, VerificationService
from dt19.signers import SignerFactory
from dt19.trust import KeyRotationService, TrustList

# Thời điểm cố định để kết quả tái lập được, không phụ thuộc lúc chạy.
NOW = datetime(2026, 10, 20, 9, 0, 0)


@pytest.fixture
def clock() -> TimestampService:
    """Đồng hồ đứng yên: kiểm thử nào cần đổi thời gian thì tự dựng cái khác."""
    return TimestampService(fixed_now=NOW)


@pytest.fixture
def repo() -> InMemoryRepository:
    return InMemoryRepository()


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Thư mục làm việc tạm, có sẵn hai artifact mẫu."""
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "app.bin").write_bytes(b"DT19-APP-" + b"\x2a" * 4096)
    (tmp_path / "artifacts" / "tailieu.txt").write_text(
        "Tai lieu huong dan\nPhien ban 1.0\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def key_factory(repo, workdir):
    """Sinh một khóa cho thuật toán bất kỳ và đăng ký vào kho."""

    def _make(alg, owner="kiem-thu", created_at=None, expires_at=None):
        signer = SignerFactory.create(alg)
        key = signer.generate_key(keys_dir=workdir / "keys", owner=owner)
        # Đồng bộ với đồng hồ cố định NOW: nếu để thời gian thật của máy,
        # chữ ký tạo lúc NOW sẽ bị coi là ký trước khi khóa tồn tại.
        key.created_at = created_at or NOW
        key.expires_at = expires_at or (NOW + timedelta(days=365))
        repo.save_key(key)
        return key

    return _make


@pytest.fixture
def trust_list(workdir):
    """Trust list rỗng phiên bản 1; từng ca tự thêm khóa cần tin."""
    return TrustList(version=1, created_at=NOW, entries=[])


@pytest.fixture
def rotation(workdir):
    return KeyRotationService(workdir / "keys", overlap_days=14)


@pytest.fixture
def signing(repo, clock, workdir):
    return SigningService(repo, clock, sig_dir=workdir / "signatures")


@pytest.fixture
def verifying(repo, trust_list, clock, workdir):
    def _make(tl=None, verifier="kiem-thu"):
        return VerificationService(
            repo,
            tl or trust_list,
            clock,
            log_path=workdir / "results" / "verify_log.jsonl",
            verifier=verifier,
        )

    return _make


@pytest.fixture
def manifest(workdir):
    m = Manifest(manifest_id="dt19-release", version=1)
    m.add_file(workdir / "artifacts" / "app.bin")
    m.add_file(workdir / "artifacts" / "tailieu.txt")
    return m
