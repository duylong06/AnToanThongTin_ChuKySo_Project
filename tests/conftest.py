"""Fixture dùng chung cho bộ kiểm thử."""

import pytest

from dt19.repository import InMemoryRepository


@pytest.fixture
def repo():
    return InMemoryRepository()


@pytest.fixture
def tmp_artifact(tmp_path):
    """Một artifact nhỏ, nội dung cố định để kết quả tái lập được."""
    p = tmp_path / "app.bin"
    p.write_bytes(b"DT19-DEMO-ARTIFACT-" + b"\x00" * 1024)
    return p
