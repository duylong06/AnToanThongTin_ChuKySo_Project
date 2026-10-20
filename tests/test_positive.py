"""Ca kiểm thử dương: ký rồi xác minh phải đạt.

Đây là baseline của toàn bộ thực nghiệm. Nếu các ca này trượt thì mọi ca âm
đều vô nghĩa, vì không chứng minh được rằng công cụ biết phân biệt đúng và sai.
"""

from __future__ import annotations

import pytest

from dt19.models import Algorithm, ReasonCode
from dt19.signers import SignerFactory
from dt19.trust import TrustEntry

from conftest import NOW

BA_THUAT_TOAN = [Algorithm.ED25519, Algorithm.ECDSA_P256, Algorithm.RSA_PSS_2048]


@pytest.mark.parametrize("alg", BA_THUAT_TOAN)
def test_tc01_ky_roi_xac_minh_phai_dat(alg, key_factory, trust_list, signing, verifying, workdir):
    """TC-01 — ký một artifact rồi xác minh, cả ba thuật toán đều phải đạt."""
    key = key_factory(alg)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_at))

    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)
    result = verifying().verify_artifact(workdir / "artifacts" / "app.bin", sig)

    assert result.passed
    assert result.reason is ReasonCode.OK


def test_tc02_ky_manifest_bao_ve_ca_bo_artifact(
    key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-02 — một chữ ký trên manifest bảo vệ được nhiều tệp cùng lúc."""
    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_at))

    sig = signing.sign_manifest(manifest, key.key_id)
    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert result.passed
    assert len(manifest.entries) == 2


@pytest.mark.parametrize("alg", BA_THUAT_TOAN)
def test_kich_thuoc_chu_ky_dung_nhu_ly_thuyet(alg, key_factory, signing, workdir):
    """Kích thước chữ ký phải khớp với con số nêu trong báo cáo.

    Ed25519 và ECDSA cho chữ ký nhỏ, RSA-PSS cho chữ ký bằng đúng kích thước
    khóa. Đây là một trong những khác biệt chính giữa ba thuật toán.
    """
    key = key_factory(alg)
    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)

    if alg is Algorithm.ED25519:
        assert sig.sig_size_bytes == 64
    elif alg is Algorithm.ECDSA_P256:
        assert 64 <= sig.sig_size_bytes <= 72
    else:
        assert sig.sig_size_bytes == 256


def test_ed25519_sinh_nonce_tat_dinh(key_factory, workdir):
    """Ed25519 ký cùng một dữ liệu hai lần cho ra chữ ký GIỐNG HỆT nhau.

    Đây là bằng chứng quan sát được của cơ chế nonce tất định k = H(prefix||M).
    ECDSA và RSA-PSS thì ngược lại, mỗi lần ký cho một chữ ký khác.
    """
    data = b"cung mot thong diep"

    ed = SignerFactory.create(Algorithm.ED25519)
    key_ed = key_factory(Algorithm.ED25519)
    assert ed.sign(data, key_ed.private_key_path) == ed.sign(data, key_ed.private_key_path)

    ec = SignerFactory.create(Algorithm.ECDSA_P256)
    key_ec = key_factory(Algorithm.ECDSA_P256)
    assert ec.sign(data, key_ec.private_key_path) != ec.sign(data, key_ec.private_key_path)
