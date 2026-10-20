"""Giao diện Signer và ba cài đặt cho ba thuật toán.

Không tự cài đặt lại thuật toán mật mã: mọi phép toán gọi qua thư viện
``cryptography``. Đề tài yêu cầu dùng API thư viện chuẩn, và tự viết lại
phép ký là cách nhanh nhất để tạo ra lỗ hổng.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.exceptions import InvalidSignature

from .models import Algorithm, KeyPair

# Hạn dùng mặc định của khóa thử nghiệm: 1 năm.
DEFAULT_VALIDITY_DAYS = 365


def _fingerprint(public_pem: str) -> str:
    """Dấu vân tay = SHA-256 của khóa công khai dạng PEM (FR-02).

    Dùng chính khóa để sinh định danh, nhờ vậy người xác minh tra được khóa
    mà không cần hỏi hệ thống nào cả.
    """
    return hashlib.sha256(public_pem.encode("utf-8")).hexdigest()


class Signer(ABC):
    """Giao diện chung cho ba thuật toán.

    Nhờ lớp trừu tượng này, SigningService và BenchmarkRunner chạy được trên
    cả ba thuật toán mà không cần biết bên trong chúng khác nhau ra sao.
    Thêm thuật toán thứ tư chỉ cần thêm một lớp con.
    """

    alg: Algorithm

    @abstractmethod
    def _generate_private_key(self): ...

    @abstractmethod
    def _load_private_key(self, pem_bytes: bytes): ...

    @abstractmethod
    def _sign_with(self, private_key, data: bytes) -> bytes: ...

    @abstractmethod
    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None: ...

    def generate_key(
        self, keys_dir: str | Path = "keys", owner: str | None = None
    ) -> KeyPair:
        """Sinh cặp khóa mới và ghi ra đĩa (FR-01, FR-02, FR-03).

        Khóa riêng ghi với quyền 600 để người dùng khác trên máy không đọc được.
        """
        private_key = self._generate_private_key()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        fp = _fingerprint(public_pem)
        key_id = fp[:16]

        alg_dir = Path(keys_dir) / self.alg.value
        alg_dir.mkdir(parents=True, exist_ok=True)
        private_path = alg_dir / f"{key_id}.key"
        private_path.write_bytes(private_pem)
        try:
            private_path.chmod(0o600)
        except (OSError, NotImplementedError):
            # Windows không hỗ trợ chmod kiểu POSIX; ghi chú trong báo cáo.
            pass
        (alg_dir / f"{key_id}.public.pem").write_text(public_pem, encoding="utf-8")

        now = datetime.now()
        return KeyPair(
            key_id=key_id,
            alg=self.alg,
            public_key_pem=public_pem,
            private_key_path=str(private_path),
            fingerprint=fp,
            created_at=now,
            expires_at=now + timedelta(days=DEFAULT_VALIDITY_DAYS),
            status="active",
            owner=owner,
        )

    def sign(self, data: bytes, private_key_path: str) -> bytes:
        """Ký ``data``, trả chuỗi byte chữ ký (FR-06)."""
        pem = Path(private_key_path).read_bytes()
        private_key = self._load_private_key(pem)
        return self._sign_with(private_key, data)

    def verify(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        """Trả True nếu chữ ký khớp.

        Không ném ngoại lệ khi chữ ký sai: chữ ký sai là kết quả bình thường
        của việc xác minh, không phải lỗi chương trình.
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
        try:
            self._verify_with(public_key, data, signature)
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Chữ ký méo mó, sai độ dài, sai định dạng: vẫn coi là không khớp.
            return False


class RsaPssSigner(Signer):
    """RSA với đệm PSS.

    Điểm cần nêu trong báo cáo: PSS dùng muối ngẫu nhiên nên hai lần ký cùng
    một thông điệp cho hai chữ ký khác nhau, và điều đó không làm lộ khóa.
    Đổi lại chữ ký rất lớn: bằng đúng kích thước khóa, tức 256 byte với
    khóa 2048 bit, gấp bốn lần Ed25519.
    """

    def __init__(self, key_size: int = 2048) -> None:
        self.key_size = key_size
        self.alg = (
            Algorithm.RSA_PSS_2048 if key_size == 2048 else Algorithm.RSA_PSS_3072
        )

    def _generate_private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

    def _load_private_key(self, pem_bytes: bytes):
        return serialization.load_pem_private_key(pem_bytes, password=None)

    @staticmethod
    def _padding() -> padding.PSS:
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

    def _sign_with(self, private_key, data: bytes) -> bytes:
        return private_key.sign(data, self._padding(), hashes.SHA256())

    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        public_key.verify(signature, data, self._padding(), hashes.SHA256())


class EcdsaSigner(Signer):
    """ECDSA trên đường cong P-256.

    Điểm cần nêu trong báo cáo: nonce k phải ngẫu nhiên và không bao giờ lặp.
    Tái sử dụng k cho hai thông điệp khác nhau dưới cùng một khóa riêng làm
    lộ TOÀN BỘ khóa riêng chỉ bằng vài phép toán số học. Thư viện chuẩn đã
    xử lý việc sinh nonce; đây chính là lý do không được tự cài đặt lại.
    """

    alg = Algorithm.ECDSA_P256

    def _generate_private_key(self):
        return ec.generate_private_key(ec.SECP256R1())

    def _load_private_key(self, pem_bytes: bytes):
        return serialization.load_pem_private_key(pem_bytes, password=None)

    def _sign_with(self, private_key, data: bytes) -> bytes:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))


class Ed25519Signer(Signer):
    """EdDSA trên đường cong Edwards xoắn Ed25519 (RFC 8032).

    Điểm cần nêu trong báo cáo: nonce sinh TẤT ĐỊNH theo k = H(prefix || M),
    trong đó prefix là chuỗi byte bí mật trích từ khóa riêng. Cùng một thông
    điệp luôn cho cùng một nonce, hai thông điệp khác nhau chắc chắn cho hai
    nonce khác nhau, nên rủi ro lộ khóa do bộ sinh số ngẫu nhiên kém bị
    triệt tiêu ngay từ thiết kế.

    Hệ quả quan sát được trong thực nghiệm: ký cùng một dữ liệu hai lần bằng
    Ed25519 cho ra hai chữ ký GIỐNG HỆT nhau, còn RSA-PSS và ECDSA thì không.
    """

    alg = Algorithm.ED25519

    def _generate_private_key(self):
        return ed25519.Ed25519PrivateKey.generate()

    def _load_private_key(self, pem_bytes: bytes):
        return serialization.load_pem_private_key(pem_bytes, password=None)

    def _sign_with(self, private_key, data: bytes) -> bytes:
        return private_key.sign(data)

    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        public_key.verify(signature, data)


class SignerFactory:
    """Chọn cài đặt theo thuật toán. Chỗ duy nhất trong hệ thống biết cả ba lớp con."""

    @staticmethod
    def create(alg: Algorithm | str) -> Signer:
        alg = Algorithm(alg)
        if alg == Algorithm.RSA_PSS_2048:
            return RsaPssSigner(2048)
        if alg == Algorithm.RSA_PSS_3072:
            return RsaPssSigner(3072)
        if alg == Algorithm.ECDSA_P256:
            return EcdsaSigner()
        if alg == Algorithm.ED25519:
            return Ed25519Signer()
        raise ValueError(f"Thuật toán không được hỗ trợ: {alg}")

    @staticmethod
    def all_algorithms() -> list[Algorithm]:
        """Ba thuật toán dùng để so sánh trong báo cáo."""
        return [Algorithm.ED25519, Algorithm.ECDSA_P256, Algorithm.RSA_PSS_2048]
