"""Giao diện Signer và ba cài đặt cho ba thuật toán.

Không tự cài đặt lại thuật toán mật mã: mọi phép toán gọi qua thư viện
``cryptography``. Đề tài yêu cầu dùng API thư viện chuẩn.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import Algorithm, KeyPair


class Signer(ABC):
    """Giao diện chung cho ba thuật toán.

    Nhờ lớp trừu tượng này, SigningService và BenchmarkRunner chạy được trên
    cả ba thuật toán mà không cần biết bên trong chúng khác nhau ra sao.
    """

    alg: Algorithm

    @abstractmethod
    def generate_key(self, owner: str | None = None) -> KeyPair:
        """Sinh cặp khóa mới, trả về bản ghi đã tính sẵn dấu vân tay (FR-01, FR-02)."""

    @abstractmethod
    def sign(self, data: bytes, private_key_path: str) -> bytes:
        """Ký ``data``, trả chuỗi byte chữ ký (FR-06)."""

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        """Trả True nếu chữ ký khớp. Không ném ngoại lệ khi chữ ký sai."""


class RsaPssSigner(Signer):
    """RSA với đệm PSS.

    Điểm cần nêu trong báo cáo: PSS dùng muối ngẫu nhiên nên hai lần ký cùng
    một thông điệp cho hai chữ ký khác nhau, và điều đó không làm lộ khóa.
    """

    def __init__(self, key_size: int = 2048) -> None:
        self.key_size = key_size
        self.alg = (
            Algorithm.RSA_PSS_2048 if key_size == 2048 else Algorithm.RSA_PSS_3072
        )

    def generate_key(self, owner: str | None = None) -> KeyPair:
        raise NotImplementedError  # TODO(A)

    def sign(self, data: bytes, private_key_path: str) -> bytes:
        raise NotImplementedError  # TODO(A)

    def verify(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        raise NotImplementedError  # TODO(A)


class EcdsaSigner(Signer):
    """ECDSA trên đường cong P-256.

    Điểm cần nêu trong báo cáo: nonce k phải ngẫu nhiên và không bao giờ lặp.
    Tái sử dụng k cho hai thông điệp khác nhau dưới cùng một khóa riêng làm
    lộ toàn bộ khóa riêng. Thư viện chuẩn đã xử lý việc này; nhóm chỉ cần
    giải thích cơ chế, KHÔNG tự cài đặt lại phép ký.
    """

    alg = Algorithm.ECDSA_P256

    def generate_key(self, owner: str | None = None) -> KeyPair:
        raise NotImplementedError  # TODO(B)

    def sign(self, data: bytes, private_key_path: str) -> bytes:
        raise NotImplementedError  # TODO(B)

    def verify(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        raise NotImplementedError  # TODO(B)


class Ed25519Signer(Signer):
    """EdDSA trên đường cong Ed25519.

    Điểm cần nêu trong báo cáo: nonce sinh tất định theo k = H(prefix || M),
    nên rủi ro tái sử dụng nonce bị triệt tiêu ngay từ thiết kế.
    Làm thuật toán này TRƯỚC vì API gọn nhất.
    """

    alg = Algorithm.ED25519

    def generate_key(self, owner: str | None = None) -> KeyPair:
        raise NotImplementedError  # TODO(C)

    def sign(self, data: bytes, private_key_path: str) -> bytes:
        raise NotImplementedError  # TODO(C)

    def verify(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        raise NotImplementedError  # TODO(C)


class SignerFactory:
    """Chọn cài đặt theo thuật toán. Chỗ duy nhất biết cả ba lớp con."""

    @staticmethod
    def create(alg: Algorithm) -> Signer:
        raise NotImplementedError  # TODO(A)
