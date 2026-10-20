# Mô hình dữ liệu — Sơ đồ ERD

Toàn bộ trạng thái của công cụ nằm trong một tệp SQLite `data/sigtool.db`.
Chọn SQLite vì nhóm nộp kèm được nguyên tệp làm minh chứng, và vì không cần
máy chủ cơ sở dữ liệu trong môi trường lab.

## 1. Sơ đồ quan hệ thực thể

```mermaid
erDiagram
    KEY_PAIR ||--o{ SIGNATURE : "ky bang"
    KEY_PAIR ||--o{ TRUST_LIST_ENTRY : "duoc tin trong"
    KEY_PAIR ||--o| REVOCATION : "bi thu hoi boi"
    KEY_PAIR ||--o{ MANIFEST : "ky"
    TRUST_LIST ||--o{ TRUST_LIST_ENTRY : "gom"
    ARTIFACT ||--o{ MANIFEST_ENTRY : "xuat hien trong"
    ARTIFACT ||--o{ SIGNATURE : "duoc ky"
    MANIFEST ||--o{ MANIFEST_ENTRY : "liet ke"
    MANIFEST ||--o{ SIGNATURE : "duoc ky"
    SIGNATURE ||--o{ VERIFICATION_LOG : "duoc xac minh"

    KEY_PAIR {
        text key_id PK "dau van tay SHA-256 rut gon"
        text alg "rsa_pss_2048 | ecdsa_p256 | ed25519"
        text public_key_pem
        text private_key_path "duong dan, khong luu noi dung"
        text fingerprint "SHA-256 day du"
        datetime created_at
        datetime expires_at
        text status "active | rotating | revoked | expired"
        text owner "thanh vien phu trach"
    }

    TRUST_LIST {
        integer version PK
        datetime created_at
        text note "ly do phat hanh phien ban nay"
        text sha256 "bam cua tep trust_list_v{version}.json"
    }

    TRUST_LIST_ENTRY {
        integer entry_id PK
        integer trust_list_version FK
        text key_id FK
        datetime valid_from
        datetime valid_to "null neu chua gioi han"
    }

    ARTIFACT {
        text artifact_id PK
        text path
        text kind "binary | document | manifest"
        integer size_bytes
        text sha256
        datetime created_at
        boolean is_tampered "true neu la ban co tinh sua de kiem thu am"
    }

    MANIFEST {
        text manifest_id PK
        integer version
        text key_id FK "khoa du kien se ky"
        text sha256
        datetime created_at
    }

    MANIFEST_ENTRY {
        integer entry_id PK
        text manifest_id FK
        text artifact_id FK
        text sha256_at_time "bam cua artifact luc lap manifest"
        integer size_at_time
    }

    SIGNATURE {
        text signature_id PK
        text target_id FK "artifact_id hoac manifest_id"
        text target_kind "artifact | manifest"
        text key_id FK
        text alg
        text sig_path "duong dan tep chu ky tach roi"
        integer sig_size_bytes
        datetime signed_at
        text timestamp_token "null neu khong gan dau thoi gian"
    }

    VERIFICATION_LOG {
        integer log_id PK
        text signature_id FK
        datetime verified_at
        text result "pass | fail"
        text reason_code "OK | SIG_INVALID | CONTENT_MODIFIED | ..."
        integer trust_list_version
        text verifier "thanh vien chay phep thu"
        real duration_ms
    }

    REVOCATION {
        integer revocation_id PK
        text key_id FK
        datetime revoked_at
        text reason "khoa bi lo | het han | ngung su dung"
        text action_taken "ky lai | canh bao | khong"
        integer affected_signatures
    }

    BENCHMARK_RUN {
        integer run_id PK
        text alg
        text operation "sign | verify"
        integer iteration
        integer payload_size_bytes
        integer key_size_bytes
        integer sig_size_bytes
        real duration_ms
        datetime run_at
        text machine "dinh danh may chay"
    }
```

`BENCHMARK_RUN` cố ý **không** nối khóa ngoại với các bảng khác: nó là dữ liệu đo
độc lập, chạy trên artifact tổng hợp, và tách riêng để xóa hoặc chạy lại mà
không ảnh hưởng dữ liệu nghiệp vụ.

## 2. Những quyết định thiết kế đáng giải thích trong báo cáo

| Quyết định | Lý do |
| --- | --- |
| `key_id` là dấu vân tay rút gọn, không phải số tự tăng | Định danh khóa phải suy ra được từ chính khóa, để người xác minh tra được mà không cần hỏi hệ thống |
| Bảng `trust_list_entry` tách riêng thay vì nhét vào `key_pair` | Một khóa có thể hiệu lực ở nhiều phiên bản trust list khác nhau; đây là quan hệ nhiều-nhiều, và nó chính là chỗ giai đoạn chồng lấn được thể hiện |
| `manifest_entry.sha256_at_time` lưu lại mã băm tại thời điểm lập manifest | Để so sánh với mã băm hiện tại của artifact; chênh lệch chính là bằng chứng nội dung bị sửa |
| `signature` lưu đường dẫn tệp chữ ký, không lưu chuỗi byte | Giữ cơ sở dữ liệu nhỏ và nộp kèm được; chữ ký vẫn là tệp độc lập đúng mô hình detached signature |
| `verification_log` không có cột cho phép sửa | Nhật ký kiểm toán phải chỉ ghi thêm; mọi lần xác minh đều để lại dấu vết |
| `artifact.is_tampered` | Đánh dấu rõ bản cố tình sửa phục vụ kiểm thử âm, tránh nhầm với lỗi thật khi đọc lại dữ liệu sau này |

## 3. Ràng buộc toàn vẹn

- `signature.key_id` phải tồn tại trong `key_pair`.
- Một `artifact` chỉ có một `sha256` tại một thời điểm; bản bị sửa là **bản ghi mới**,
  không phải cập nhật bản cũ.
- `trust_list_entry.valid_to` nếu khác null thì phải lớn hơn `valid_from`.
- `revocation.key_id` là duy nhất: một khóa chỉ bị thu hồi một lần.
- `verification_log.reason_code` phải thuộc tập mã lý do trong tài liệu đặc tả yêu cầu.
