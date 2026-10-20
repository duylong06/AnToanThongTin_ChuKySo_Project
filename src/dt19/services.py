"""Tầng nghiệp vụ: ký, xác minh, thu hồi, đo hiệu năng."""

from __future__ import annotations

from datetime import datetime

from .models import Algorithm, Manifest, Signature, VerificationResult
from .repository import Repository
from .trust import TrustList


class TimestampService:
    """Dấu thời gian mô phỏng cục bộ.

    Tách riêng để kiểm thử bơm được thời gian giả: muốn kiểm tra tình huống
    "khóa hết hạn tại thời điểm ký" mà phải chờ khóa hết hạn thật thì không
    kiểm thử được.
    """

    def now(self) -> datetime:
        return datetime.now()

    def issue_token(self, digest: bytes) -> str:
        raise NotImplementedError  # TODO(C)

    def check_token(self, token: str, digest: bytes) -> bool:
        raise NotImplementedError  # TODO(C)


class SigningService:
    def __init__(self, repo: Repository, clock: TimestampService) -> None:
        self.repo = repo
        self.clock = clock

    def sign_artifact(self, path: str, alg: Algorithm) -> Signature:
        """TODO(A): FR-06, FR-08, FR-09."""
        raise NotImplementedError

    def sign_manifest(self, manifest: Manifest, alg: Algorithm) -> Signature:
        """TODO(A): FR-07."""
        raise NotImplementedError


class VerificationService:
    def __init__(
        self, repo: Repository, trust_list: TrustList, log_path: str
    ) -> None:
        self.repo = repo
        self.trust_list = trust_list
        self.log_path = log_path

    def verify(self, artifact_path: str, sig_path: str) -> VerificationResult:
        """Xác minh và ghi nhật ký (FR-10, FR-11, FR-13).

        Thứ tự kiểm tra có chủ ý: tra trust list TRƯỚC khi kiểm tra chữ ký,
        để một khóa lạ trả về KEY_UNKNOWN chứ không trả về SIG_INVALID.

        TODO(B).
        """
        raise NotImplementedError


class RevocationService:
    """Thu hồi khóa và xử lý hậu quả (FR-17, FR-18, FR-19)."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def revoke(self, key_id: str, reason: str, now: datetime) -> None:
        raise NotImplementedError  # TODO(C)

    def list_affected(self, key_id: str) -> list[Signature]:
        raise NotImplementedError  # TODO(C)

    def resign_all(self, key_id: str, new_key_id: str) -> int:
        raise NotImplementedError  # TODO(C)


class BenchmarkRunner:
    """Đo thời gian ký và xác minh (FR-20, FR-21, NFR-02)."""

    def __init__(self, iterations: int = 100) -> None:
        self.iterations = iterations

    def run(self, alg: Algorithm, payload_size: int) -> list[dict]:
        """Lặp ``iterations`` lần, trả về một dict cho mỗi lần đo.

        Đo bằng time.perf_counter. Không lấy trung bình ở đây: xuất từng lần
        đo ra CSV rồi tính trung vị và phân vị 95 ở bước phân tích, như vậy
        dữ liệu thô vẫn còn để kiểm chứng.

        TODO(A).
        """
        raise NotImplementedError

    def export_csv(self, rows: list[dict], path: str) -> None:
        """Cột: alg, thao_tac, lan, kich_thuoc_khoa_byte,
        kich_thuoc_chu_ky_byte, thoi_gian_ms. TODO(A)."""
        raise NotImplementedError
