"""Ca kiểm thử âm: mọi sửa đổi đều phải làm xác minh thất bại.

Đề bài yêu cầu riêng mục này (yêu cầu thực nghiệm số 3). Ba loại sai lệch
phải phân biệt được bằng MÃ LÝ DO khác nhau, không chỉ cùng trả về "sai".
"""

import pytest


def test_sua_mot_byte_noi_dung_phai_truot():
    """TC-03 — kỳ vọng: CONTENT_MODIFIED."""
    pytest.skip("TODO(B)")


def test_sua_metadata_trong_manifest_phai_truot():
    """TC-04 — kỳ vọng: METADATA_MODIFIED."""
    pytest.skip("TODO(B)")


def test_thay_chu_ky_bang_chu_ky_khac_phai_truot():
    """TC-05 — kỳ vọng: SIG_INVALID."""
    pytest.skip("TODO(B)")


def test_khoa_khong_trong_trust_list_phai_truot():
    """TC-06 — kỳ vọng: KEY_UNKNOWN, không phải SIG_INVALID.

    Thứ tự kiểm tra trong VerificationService quyết định ca này.
    """
    pytest.skip("TODO(B)")
