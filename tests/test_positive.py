"""Ca kiểm thử dương: ký rồi xác minh phải đạt.

Đây là baseline. Nếu ca này trượt thì mọi ca âm đều vô nghĩa.
"""

import pytest

from dt19.models import Algorithm


@pytest.mark.parametrize(
    "alg",
    [Algorithm.ED25519, Algorithm.ECDSA_P256, Algorithm.RSA_PSS_2048],
)
def test_ky_roi_xac_minh_phai_dat(alg):
    """TC-01 — minh chứng: chữ ký và log xác minh."""
    pytest.skip("TODO(B): hiện thực sau khi sign/verify chạy được")


def test_ky_manifest_bao_ve_ca_bo_artifact():
    """TC-02 — một chữ ký trên manifest bảo vệ nhiều tệp."""
    pytest.skip("TODO(B)")
