"""Ca kiểm thử âm: mọi sửa đổi đều phải làm xác minh thất bại.

Đề bài yêu cầu riêng mục này. Điểm mấu chốt: ba loại sai lệch phải phân biệt
được bằng MÃ LÝ DO khác nhau, không chỉ cùng trả về "sai". Người dùng cần
biết sai ở đâu để xử lý, và nhật ký cần ghi lại được nguyên nhân.
"""

from __future__ import annotations

import json

from dt19.models import Algorithm, ReasonCode
from dt19.trust import TrustEntry


def _ky_manifest(key_factory, trust_list, signing, manifest):
    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_at))
    return key, signing.sign_manifest(manifest, key.key_id)


def test_tc03_sua_mot_byte_noi_dung_phai_truot(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-03 — sửa đúng một byte trong tệp. Kỳ vọng: CONTENT_MODIFIED."""
    _, sig = _ky_manifest(key_factory, trust_list, signing, manifest)

    target = workdir / "artifacts" / "app.bin"
    data = bytearray(target.read_bytes())
    data[100] ^= 0x01
    target.write_bytes(data)

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.CONTENT_MODIFIED
    assert "app.bin" in result.detail


def test_tc04_doi_ten_tep_phai_bao_metadata(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-04 — đổi tên tệp, nội dung giữ nguyên. Kỳ vọng: METADATA_MODIFIED.

    Đây là tấn công tráo tên: ruột tệp hợp lệ nhưng được đặt vào vị trí mà
    người dùng tưởng là thứ khác.
    """
    _, sig = _ky_manifest(key_factory, trust_list, signing, manifest)

    cu = workdir / "artifacts" / "tailieu.txt"
    cu.rename(workdir / "artifacts" / "tailieu_v2.txt")

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.METADATA_MODIFIED


def test_tc05_sua_manifest_da_ky_phai_truot(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-05 — sửa chính manifest đã ký. Kỳ vọng: SIG_INVALID.

    Khác với TC-03: ở đây phần ĐƯỢC KÝ bị sửa, nên hỏng ngay ở bước mật mã,
    chưa cần đối chiếu tệp trên đĩa.
    """
    _, sig = _ky_manifest(key_factory, trust_list, signing, manifest)

    manifest.entries[0].size_at_time = 999999

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.SIG_INVALID


def test_tc06_thay_chu_ky_bang_rac_phai_truot(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-06 — thay tệp chữ ký bằng dữ liệu rác. Kỳ vọng: SIG_INVALID."""
    _, sig = _ky_manifest(key_factory, trust_list, signing, manifest)

    from pathlib import Path

    Path(sig.sig_path).write_bytes(b"X" * 64)

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.SIG_INVALID


def test_tc07_khoa_khong_trong_trust_list_phai_bao_key_unknown(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-07 — khóa ký đúng nhưng không được tin. Kỳ vọng: KEY_UNKNOWN.

    Ca này chứng minh thứ tự kiểm tra trong VerificationService là đúng: tra
    trust list trước, nên trả về KEY_UNKNOWN chứ không phải SIG_INVALID,
    dù về mặt mật mã chữ ký hoàn toàn hợp lệ.
    """
    key = key_factory(Algorithm.ED25519)
    # Cố ý KHÔNG thêm khóa vào trust list.
    sig = signing.sign_manifest(manifest, key.key_id)

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.KEY_UNKNOWN


def test_tc08_nhat_ky_chi_ghi_them(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-08 — mỗi lần xác minh để lại đúng một dòng, dòng cũ không bị sửa."""
    _, sig = _ky_manifest(key_factory, trust_list, signing, manifest)
    service = verifying()

    service.verify_manifest(manifest, sig, workdir / "artifacts")
    sau_lan_1 = (workdir / "results" / "verify_log.jsonl").read_text(encoding="utf-8")

    service.verify_manifest(manifest, sig, workdir / "artifacts")
    sau_lan_2 = (workdir / "results" / "verify_log.jsonl").read_text(encoding="utf-8")

    assert sau_lan_2.startswith(sau_lan_1), "dong cu da bi sua"
    assert len(sau_lan_2.strip().splitlines()) == 2

    ban_ghi = json.loads(sau_lan_2.strip().splitlines()[0])
    assert ban_ghi["reason_code"] == "OK"
    assert "private" not in sau_lan_2 and "BEGIN" not in sau_lan_2, "log lo khoa rieng"
