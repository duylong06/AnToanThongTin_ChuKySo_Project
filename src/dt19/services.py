"""Tầng nghiệp vụ: ký, xác minh, thu hồi, đo hiệu năng.

Tầng này không biết dữ liệu nằm ở SQLite hay trong bộ nhớ, cũng không biết
thuật toán nào đang chạy. Nó chỉ làm việc với các giao diện ``Repository``
và ``Signer``.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime
from pathlib import Path

from .models import (
    Algorithm,
    Manifest,
    ReasonCode,
    Signature,
    VerificationResult,
    sha256_bytes,
    sha256_file,
)
from .repository import Repository
from .signers import SignerFactory
from .trust import TrustList

# Khóa bí mật của dịch vụ dấu thời gian mô phỏng. Trong hệ thống thật đây là
# khóa của một TSA độc lập; ở đồ án nhóm giữ cục bộ và nêu rõ là giả lập.
_TSA_SECRET = b"dt19-tsa-khoa-mo-phong-chi-dung-cho-do-an"


class TimestampService:
    """Dấu thời gian mô phỏng cục bộ (FR-08).

    Tách riêng vì hai lý do. Thứ nhất, kiểm thử cần bơm thời gian giả: muốn
    kiểm tra "khóa hết hạn tại thời điểm ký" mà phải chờ khóa hết hạn thật
    thì không kiểm thử được. Thứ hai, nếu sau này thay bằng TSA chuẩn RFC
    3161 thì chỉ đổi lớp này.

    GIỚI HẠN: đây KHÔNG phải dấu thời gian có giá trị trước bên thứ ba, vì
    chính nhóm giữ khóa ký dấu. Phải nêu rõ trong báo cáo.
    """

    def __init__(self, fixed_now: datetime | None = None) -> None:
        self._fixed_now = fixed_now

    def now(self) -> datetime:
        return self._fixed_now or datetime.now()

    def issue_token(self, digest: str) -> str:
        """Token = thời điểm + HMAC(thời điểm || digest)."""
        ts = self.now().isoformat()
        mac = hmac.new(
            _TSA_SECRET, f"{ts}|{digest}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{ts}|{mac}"

    def check_token(self, token: str, digest: str) -> bool:
        try:
            ts, mac = token.rsplit("|", 1)
        except ValueError:
            return False
        expected = hmac.new(
            _TSA_SECRET, f"{ts}|{digest}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(mac, expected)

    def token_time(self, token: str) -> datetime | None:
        try:
            return datetime.fromisoformat(token.rsplit("|", 1)[0])
        except (ValueError, IndexError):
            return None


class SigningService:
    """Ký artifact và manifest (FR-06, FR-07, FR-08, FR-09)."""

    def __init__(
        self,
        repo: Repository,
        clock: TimestampService | None = None,
        sig_dir: str | Path = "signatures",
    ) -> None:
        self.repo = repo
        self.clock = clock or TimestampService()
        self.sig_dir = Path(sig_dir)

    def _sign_bytes(
        self, data: bytes, key_id: str, target_id: str, target_kind: str
    ) -> Signature:
        key = self.repo.get_key(key_id)
        if key is None:
            raise ValueError(f"Khong tim thay khoa {key_id}")

        signer = SignerFactory.create(key.alg)
        sig_bytes = signer.sign(data, key.private_key_path)

        self.sig_dir.mkdir(parents=True, exist_ok=True)
        sig_path = self.sig_dir / f"{target_id}.{key.alg.value}.sig"
        sig_path.write_bytes(sig_bytes)

        digest = sha256_bytes(data)
        signature = Signature(
            signature_id=f"{target_id}:{key_id}:{secrets.token_hex(4)}",
            target_id=target_id,
            target_kind=target_kind,
            key_id=key_id,
            alg=key.alg,
            sig_path=str(sig_path),
            sig_size_bytes=len(sig_bytes),
            signed_at=self.clock.now(),
            timestamp_token=self.clock.issue_token(digest),
        )
        self.repo.save_signature(signature)
        return signature

    def sign_artifact(self, path: str | Path, key_id: str) -> Signature:
        """Ký trực tiếp nội dung một tệp."""
        data = Path(path).read_bytes()
        return self._sign_bytes(data, key_id, Path(path).name, "artifact")

    def sign_manifest(self, manifest: Manifest, key_id: str) -> Signature:
        """Ký manifest: một chữ ký bảo vệ cả bộ artifact."""
        manifest.key_id = key_id
        return self._sign_bytes(
            manifest.canonical_bytes(), key_id, manifest.manifest_id, "manifest"
        )


class VerificationService:
    """Xác minh chữ ký và ghi nhật ký (FR-10 đến FR-14).

    THỨ TỰ KIỂM TRA CÓ CHỦ Ý, và đây là chi tiết đáng viết trong báo cáo:
    tra trust list TRƯỚC khi kiểm tra chữ ký. Nếu làm ngược lại, một khóa lạ
    nhưng ký đúng sẽ trả về OK ở bước mật mã rồi mới bị chặn, và thông báo
    lỗi sẽ không nói được rằng vấn đề nằm ở sự tin cậy chứ không ở phép toán.
    """

    def __init__(
        self,
        repo: Repository,
        trust_list: TrustList,
        clock: TimestampService | None = None,
        log_path: str | Path = "results/verify_log.jsonl",
        verifier: str | None = None,
    ) -> None:
        self.repo = repo
        self.trust_list = trust_list
        self.clock = clock or TimestampService()
        self.log_path = Path(log_path)
        self.verifier = verifier

    def _log(self, sig: Signature | None, result: VerificationResult) -> None:
        """Ghi nhật ký chỉ cho phép ghi thêm (NFR-05).

        Mở tệp ở chế độ "a": không có đường nào sửa dòng cũ qua API này.
        """
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "verified_at": datetime.now().isoformat(),
            "signature_id": sig.signature_id if sig else None,
            "target_id": sig.target_id if sig else None,
            "key_id": sig.key_id if sig else None,
            "alg": sig.alg.value if sig else None,
            "result": "pass" if result.passed else "fail",
            "reason_code": result.reason.value,
            "detail": result.detail,
            "trust_list_version": self.trust_list.version,
            "verifier": self.verifier,
            "duration_ms": round(result.duration_ms, 4),
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        if sig is not None:
            try:
                self.repo.log_verification(
                    signature_id=sig.signature_id,
                    result="pass" if result.passed else "fail",
                    reason_code=result.reason.value,
                    verifier=self.verifier,
                    duration_ms=result.duration_ms,
                    trust_list_version=self.trust_list.version,
                )
            except Exception:
                # Nhật ký JSONL là nguồn chính; lỗi ghi cơ sở dữ liệu không
                # được làm hỏng kết quả xác minh.
                pass

    def _check_key(self, sig: Signature) -> tuple[ReasonCode, str | None]:
        """Kiểm tra tính tin cậy của khóa tại THỜI ĐIỂM KÝ, không phải hiện tại."""
        key = self.repo.get_key(sig.key_id)
        if key is None:
            return ReasonCode.KEY_UNKNOWN, f"khoa {sig.key_id}"

        revoked_at = self.repo.get_revocation(sig.key_id)
        if revoked_at is not None and sig.signed_at >= revoked_at:
            return ReasonCode.KEY_REVOKED, f"thu hoi luc {revoked_at:%d/%m/%Y %H:%M}"

        if not self.trust_list.is_trusted(sig.key_id, sig.signed_at):
            # Khóa có trong kho nhưng không được tin tại thời điểm ký: hoặc
            # chưa từng vào trust list, hoặc đã hết giai đoạn chồng lấn.
            in_list = any(e.key_id == sig.key_id for e in self.trust_list.entries)
            if in_list:
                return ReasonCode.KEY_EXPIRED, "ngoai khoang hieu luc"
            return ReasonCode.KEY_UNKNOWN, f"khoa {sig.key_id} khong trong trust list"

        if key.expires_at is not None and sig.signed_at > key.expires_at:
            return ReasonCode.KEY_EXPIRED, "khoa het han"

        return ReasonCode.OK, None

    def verify_signature(
        self, data: bytes, sig: Signature, sig_bytes: bytes | None = None
    ) -> VerificationResult:
        """Xác minh một chuỗi byte đã biết trước, dùng chung cho mọi lối vào."""
        started = time.perf_counter()

        reason, detail = self._check_key(sig)
        if reason is not ReasonCode.OK:
            result = VerificationResult(
                False, reason, (time.perf_counter() - started) * 1000, detail
            )
            self._log(sig, result)
            return result

        # Kiểm tra chữ ký TRƯỚC dấu thời gian. Dấu thời gian gắn với mã băm
        # của dữ liệu, nên mọi sửa đổi nội dung đều làm nó sai theo. Nếu kiểm
        # dấu thời gian trước, một tệp bị sửa sẽ báo TIMESTAMP_INVALID trong
        # khi nguyên nhân thật là chữ ký không còn khớp — thông báo sai chỗ.
        key = self.repo.get_key(sig.key_id)
        signer = SignerFactory.create(sig.alg)
        if sig_bytes is None:
            sig_bytes = Path(sig.sig_path).read_bytes()

        if not signer.verify(data, sig_bytes, key.public_key_pem):
            result = VerificationResult(
                False,
                ReasonCode.SIG_INVALID,
                (time.perf_counter() - started) * 1000,
                "noi dung da ky bi sua hoac chu ky khong dung",
            )
            self._log(sig, result)
            return result

        # Chữ ký đã đúng; nếu dấu thời gian vẫn sai thì chính token bị giả mạo.
        if sig.timestamp_token:
            if not self.clock.check_token(sig.timestamp_token, sha256_bytes(data)):
                result = VerificationResult(
                    False,
                    ReasonCode.TIMESTAMP_INVALID,
                    (time.perf_counter() - started) * 1000,
                )
                self._log(sig, result)
                return result

        result = VerificationResult(
            True, ReasonCode.OK, (time.perf_counter() - started) * 1000
        )
        self._log(sig, result)
        return result

    def verify_artifact(self, path: str | Path, sig: Signature) -> VerificationResult:
        """Xác minh một tệp đơn lẻ."""
        return self.verify_signature(Path(path).read_bytes(), sig)

    def verify_manifest(
        self, manifest: Manifest, sig: Signature, root_dir: str | Path
    ) -> VerificationResult:
        """Xác minh manifest rồi đối chiếu từng tệp trên đĩa.

        Hai bước tách bạch, trả về hai mã lý do khác nhau: chữ ký sai là
        SIG_INVALID, còn chữ ký đúng mà tệp bị sửa là CONTENT_MODIFIED.
        """
        result = self.verify_signature(manifest.canonical_bytes(), sig)
        if not result.passed:
            return result

        started = time.perf_counter()
        reason, detail = manifest.verify_contents(root_dir)
        if reason is not ReasonCode.OK:
            bad = VerificationResult(
                False, reason, (time.perf_counter() - started) * 1000, detail
            )
            self._log(sig, bad)
            return bad
        return result


class RevocationService:
    """Thu hồi khóa và xử lý hậu quả (FR-17, FR-18, FR-19)."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def revoke(
        self,
        key_id: str,
        reason: str,
        revoked_at: datetime,
        suspected_since: datetime | None = None,
    ) -> int:
        """Thu hồi khóa, trả về số chữ ký bị ảnh hưởng.

        ``revoked_at`` là mốc cắt hiệu lực trong trust list.

        ``suspected_since`` là thời điểm NGHI NGỜ BỊ LỘ, thường sớm hơn nhiều
        so với lúc phát hiện. Chữ ký tạo từ mốc này trở đi bị coi là không
        đáng tin.

        Bỏ trống ``suspected_since`` nghĩa là KHÔNG BIẾT khóa lộ từ bao giờ.
        Khi đó phải giả định trường hợp xấu nhất và coi mọi chữ ký của khóa
        này đều đáng ngờ, thay vì báo con số 0 gây hiểu nhầm là an toàn.
        """
        affected = self.list_affected(key_id, suspected_since)
        self.repo.set_key_status(key_id, "revoked")
        self.repo.save_revocation(key_id, reason, revoked_at, len(affected))
        return len(affected)

    def list_affected(
        self, key_id: str, since: datetime | None = None
    ) -> list[Signature]:
        """Chữ ký tạo bằng khóa này; nếu có ``since`` thì chỉ lấy từ mốc đó trở đi."""
        sigs = self.repo.find_signatures_by_key(key_id)
        if since is None:
            return sigs
        return [s for s in sigs if s.signed_at >= since]


class BenchmarkRunner:
    """Đo thời gian ký và xác minh (FR-20, FR-21, NFR-02).

    Không lấy trung bình ở đây: xuất TỪNG lần đo ra CSV rồi mới tính trung vị
    và phân vị 95 ở bước phân tích. Như vậy dữ liệu thô vẫn còn để kiểm chứng,
    và người đọc báo cáo tự tính lại được.
    """

    def __init__(self, iterations: int = 100, keys_dir: str | Path = "keys") -> None:
        self.iterations = iterations
        self.keys_dir = Path(keys_dir)

    def run(
        self, algorithms: list[Algorithm] | None = None, payload_size: int = 1024 * 1024
    ) -> list[dict]:
        algorithms = algorithms or SignerFactory.all_algorithms()
        payload = os.urandom(payload_size)
        machine = f"{os.name}-python{os.sys.version_info.major}.{os.sys.version_info.minor}"
        rows: list[dict] = []
        run_at = datetime.now().isoformat(timespec="seconds")

        for alg in algorithms:
            signer = SignerFactory.create(alg)
            key = signer.generate_key(keys_dir=self.keys_dir / "bench", owner="bench")
            key_size = len(Path(key.private_key_path).read_bytes())

            for i in range(1, self.iterations + 1):
                t0 = time.perf_counter()
                sig = signer.sign(payload, key.private_key_path)
                t1 = time.perf_counter()
                rows.append(
                    {
                        "alg": alg.value,
                        "thao_tac": "sign",
                        "lan": i,
                        "kich_thuoc_payload_byte": payload_size,
                        "kich_thuoc_khoa_byte": key_size,
                        "kich_thuoc_chu_ky_byte": len(sig),
                        "thoi_gian_ms": round((t1 - t0) * 1000, 4),
                        "run_at": run_at,
                        "machine": machine,
                    }
                )

                t0 = time.perf_counter()
                signer.verify(payload, sig, key.public_key_pem)
                t1 = time.perf_counter()
                rows.append(
                    {
                        "alg": alg.value,
                        "thao_tac": "verify",
                        "lan": i,
                        "kich_thuoc_payload_byte": payload_size,
                        "kich_thuoc_khoa_byte": key_size,
                        "kich_thuoc_chu_ky_byte": len(sig),
                        "thoi_gian_ms": round((t1 - t0) * 1000, 4),
                        "run_at": run_at,
                        "machine": machine,
                    }
                )
        return rows

    @staticmethod
    def export_csv(rows: list[dict], path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def summarize(rows: list[dict]) -> list[dict]:
        """Trung vị và phân vị 95 theo từng thuật toán và thao tác."""
        import statistics

        groups: dict[tuple[str, str], list[float]] = {}
        sizes: dict[tuple[str, str], tuple[int, int]] = {}
        for r in rows:
            k = (r["alg"], r["thao_tac"])
            groups.setdefault(k, []).append(r["thoi_gian_ms"])
            sizes[k] = (r["kich_thuoc_khoa_byte"], r["kich_thuoc_chu_ky_byte"])

        out = []
        for (alg, op), values in groups.items():
            values.sort()
            n = len(values)
            out.append(
                {
                    "alg": alg,
                    "thao_tac": op,
                    "so_lan": n,
                    "trung_vi_ms": round(statistics.median(values), 4),
                    "p95_ms": round(values[min(int(n * 0.95), n - 1)], 4),
                    "nho_nhat_ms": round(values[0], 4),
                    "lon_nhat_ms": round(values[-1], 4),
                    "kich_thuoc_khoa_byte": sizes[(alg, op)][0],
                    "kich_thuoc_chu_ky_byte": sizes[(alg, op)][1],
                }
            )
        return out
