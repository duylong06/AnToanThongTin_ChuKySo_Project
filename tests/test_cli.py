"""Kiểm thử giao diện dòng lệnh từ đầu đến cuối (FR-23).

Khác với các tệp kiểm thử kia vốn gọi thẳng vào lớp nghiệp vụ, ở đây chạy
đúng cách người dùng chạy: qua ``python -m dt19``. Ca này bắt được những lỗi
chỉ lộ ra khi ghép mọi thứ lại, ví dụ sai đường dẫn hay quên khởi tạo
cơ sở dữ liệu.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from dt19.cli import main


@pytest.fixture
def cli_workdir(tmp_path, monkeypatch):
    """Thư mục trắng có hai artifact, mọi lệnh chạy bên trong nó."""
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "app.bin").write_bytes(b"DT19-CLI-" + b"\x07" * 2048)
    (tmp_path / "artifacts" / "doc.txt").write_text("noi dung mau\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _key_id() -> str:
    con = sqlite3.connect("data/sigtool.db")
    return con.execute("SELECT key_id FROM key_pair LIMIT 1").fetchone()[0]


def _signature_id() -> str:
    con = sqlite3.connect("data/sigtool.db")
    return con.execute(
        "SELECT signature_id FROM signature ORDER BY rowid DESC LIMIT 1"
    ).fetchone()[0]


def test_luong_day_du_qua_dong_lenh(cli_workdir, capsys):
    """Khởi tạo, sinh khóa, lập manifest, ký, xác minh — toàn bộ phải trôi."""
    assert main(["init"]) == 0
    assert main(["keygen", "--alg", "ed25519", "--owner", "Nguyen Duy Long"]) == 0
    assert Path("keys/trust_list_v1.json").exists()

    assert main(["keys"]) == 0
    key_id = _key_id()

    assert main(["manifest", "--dir", "artifacts", "--out", "artifacts/manifest.json"]) == 0
    manifest = json.loads(Path("artifacts/manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == 2

    assert main(["sign", "artifacts/manifest.json", "--key", key_id, "--manifest"]) == 0
    sig_id = _signature_id()

    # Mã thoát 0 nghĩa là xác minh đạt; script CI dựa vào đúng quy ước này.
    assert main(["verify", "artifacts/manifest.json", "--sig", sig_id]) == 0

    out = capsys.readouterr().out
    assert "DAT" in out and "OK" in out


def test_sua_artifact_thi_dong_lenh_tra_ma_thoat_khac_khong(cli_workdir, capsys):
    """Sửa tệp sau khi ký, lệnh verify phải trả mã thoát 1."""
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id()
    main(["manifest", "--dir", "artifacts", "--out", "artifacts/manifest.json"])
    main(["sign", "artifacts/manifest.json", "--key", key_id, "--manifest"])
    sig_id = _signature_id()

    target = Path("artifacts/app.bin")
    data = bytearray(target.read_bytes())
    data[10] ^= 0xFF
    target.write_bytes(data)

    assert main(["verify", "artifacts/manifest.json", "--sig", sig_id]) == 1
    assert "CONTENT_MODIFIED" in capsys.readouterr().out


def test_luan_chuyen_va_thu_hoi_khoa_qua_dong_lenh(cli_workdir, capsys):
    """rotate nâng phiên bản trust list, revoke đếm đúng chữ ký bị ảnh hưởng."""
    main(["init"])
    main(["keygen", "--alg", "ed25519", "--owner", "cu"])
    cu = _key_id()
    main(["sign", "artifacts/app.bin", "--key", cu])

    main(["keygen", "--alg", "ed25519", "--owner", "moi"])
    con = sqlite3.connect("data/sigtool.db")
    moi = con.execute(
        "SELECT key_id FROM key_pair ORDER BY rowid DESC LIMIT 1"
    ).fetchone()[0]

    assert main(["rotate", "--old", cu, "--new", moi]) == 0
    assert Path("keys/trust_list_v2.json").exists()

    assert main(["affected", "--key", cu]) == 0
    assert main(["revoke", "--key", cu, "--reason", "khoa bi lo"]) == 0

    out = capsys.readouterr().out
    assert "So chu ky bi anh huong: 1" in out


def test_bench_sinh_du_so_dong_va_du_cot(cli_workdir):
    """bench với 3 lần lặp phải cho 18 dòng: 3 thuật toán x 2 thao tác x 3 lần."""
    main(["bench", "--iterations", "3", "--size", "4096", "--out", "results/bench.csv"])

    dong = Path("results/bench.csv").read_text(encoding="utf-8").strip().splitlines()
    assert len(dong) == 19  # 1 dòng tiêu đề + 18 dòng dữ liệu

    tieu_de = dong[0].split(",")
    for cot in ("alg", "thao_tac", "lan", "kich_thuoc_chu_ky_byte", "thoi_gian_ms"):
        assert cot in tieu_de
