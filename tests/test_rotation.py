"""Luân chuyển khóa, giai đoạn chồng lấn và thu hồi.

Phần này kiểm chứng vòng đời khóa — nội dung mục 4.8 của bài giảng và là
một trong những yêu cầu thực nghiệm của đề tài.
"""

from __future__ import annotations

from datetime import timedelta

from dt19.models import Algorithm, ReasonCode
from dt19.services import TimestampService, VerificationService
from dt19.trust import TrustEntry

from conftest import NOW


def test_tc09_trong_giai_doan_chong_lan_khoa_cu_van_duoc_tin(
    repo, key_factory, rotation, signing, manifest, workdir
):
    """TC-09 — chữ ký bằng khóa cũ vẫn xác minh được trong 14 ngày chồng lấn."""
    cu = key_factory(Algorithm.ED25519, owner="khoa-cu")
    moi = key_factory(Algorithm.ED25519, owner="khoa-moi")

    rotation.publish_initial(cu.key_id, NOW)
    sig = signing.sign_manifest(manifest, cu.key_id)
    tl = rotation.rotate(cu.key_id, moi.key_id, NOW)

    assert tl.version == 2
    assert tl.is_trusted(cu.key_id, NOW + timedelta(days=7))
    assert tl.is_trusted(moi.key_id, NOW)

    service = VerificationService(
        repo, tl, TimestampService(fixed_now=NOW),
        log_path=workdir / "results" / "verify_log.jsonl",
    )
    assert service.verify_manifest(manifest, sig, workdir / "artifacts").passed


def test_tc10_sau_giai_doan_chong_lan_khoa_cu_het_hieu_luc(
    repo, key_factory, rotation, signing, manifest, workdir
):
    """TC-10 — quá 14 ngày, chữ ký cũ bị từ chối. Kỳ vọng: KEY_EXPIRED."""
    cu = key_factory(Algorithm.ED25519)
    moi = key_factory(Algorithm.ED25519)

    rotation.publish_initial(cu.key_id, NOW)
    tl = rotation.rotate(cu.key_id, moi.key_id, NOW)

    # Ký ở thời điểm đã quá giai đoạn chồng lấn.
    muon = NOW + timedelta(days=20)
    signing.clock = TimestampService(fixed_now=muon)
    sig = signing.sign_manifest(manifest, cu.key_id)

    service = VerificationService(
        repo, tl, TimestampService(fixed_now=muon),
        log_path=workdir / "results" / "verify_log.jsonl",
    )
    result = service.verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.KEY_EXPIRED


def test_tc11_khoa_bi_thu_hoi_thi_chu_ky_sau_moc_do_bi_tu_choi(
    repo, key_factory, trust_list, signing, verifying, manifest, workdir
):
    """TC-11 — chữ ký tạo sau thời điểm thu hồi. Kỳ vọng: KEY_REVOKED."""
    from dt19.services import RevocationService

    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_at))

    sig = signing.sign_manifest(manifest, key.key_id)
    RevocationService(repo).revoke(
        key.key_id, "khoa bi lo", NOW - timedelta(hours=1)
    )

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.KEY_REVOKED


def test_tc12_liet_ke_dung_so_artifact_bi_anh_huong(
    repo, key_factory, trust_list, signing, manifest, workdir
):
    """TC-12 — đếm đúng số chữ ký của khóa bị lộ, đầu vào của runbook (FR-18)."""
    from dt19.services import RevocationService

    key = key_factory(Algorithm.ED25519)
    khac = key_factory(Algorithm.ECDSA_P256)

    signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)
    signing.sign_artifact(workdir / "artifacts" / "tailieu.txt", key.key_id)
    signing.sign_artifact(workdir / "artifacts" / "app.bin", khac.key_id)

    service = RevocationService(repo)
    assert len(service.list_affected(key.key_id)) == 2
    assert service.revoke(key.key_id, "khoa bi lo", NOW) == 2
    assert repo.get_key(key.key_id).status == "revoked"
