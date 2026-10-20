# Đặc tả yêu cầu phần mềm (SRS)

**Đồ án:** Đề tài 19 — Đánh giá chữ ký số cho phần mềm và tài liệu điện tử
**Học phần:** An toàn thông tin (123033) — TS. Lê Quốc Tuấn
**Nhóm:** 19 (3 thành viên)
**Phiên bản tài liệu:** 0.1 — 20/10/2026

---

## 1. Mục đích và phạm vi

### 1.1. Mục đích

Xây dựng một công cụ dòng lệnh (gọi là **sigtool**) cho phép ký và xác minh artifact
bằng ba thuật toán chữ ký số RSA-PSS, ECDSA và Ed25519, đồng thời **đo được**
sự khác biệt giữa chúng và **chứng minh được** rằng mọi thay đổi trên nội dung
hoặc metadata đều làm xác minh thất bại.

Công cụ không nhằm thay thế sản phẩm thương mại. Nó là nguyên mẫu phục vụ
thực nghiệm có kiểm soát, để nhóm rút ra kết luận có số liệu kèm theo.

### 1.2. Phạm vi

**Trong phạm vi:**

- Sinh, lưu trữ và quản lý vòng đời khóa thử nghiệm cho ba thuật toán.
- Tạo manifest có phiên bản, ký và xác minh artifact lẫn manifest.
- Gắn và kiểm tra dấu thời gian.
- Danh sách khóa tin cậy (trust list) theo phiên bản, luân chuyển khóa có giai đoạn chồng lấn.
- Quy trình xử lý khóa bị lộ: thu hồi, ký lại, cảnh báo.
- Đo hiệu năng và xuất dữ liệu dạng CSV.

**Ngoài phạm vi:**

- Hạ tầng khóa công khai đầy đủ với CA gốc và CA trung gian (đó là đề tài 20).
- Giao diện đồ họa.
- Dịch vụ dấu thời gian đạt chuẩn RFC 3161 của bên thứ ba. Nhóm mô phỏng cục bộ
  và nêu rõ đây là giả lập.
- Ký phần mềm thật bằng danh tính hoặc chứng thư của tổ chức. **Nghiêm cấm.**

### 1.3. Định nghĩa thuật ngữ

| Thuật ngữ | Giải thích |
| --- | --- |
| Artifact | Sản phẩm số được ký: file nhị phân, tài liệu, hoặc manifest |
| Manifest | File liệt kê tên, kích thước và mã băm SHA-256 của các artifact khác |
| Dấu vân tay khóa | Mã băm SHA-256 của khóa công khai, dùng để nhận diện khóa ngắn gọn |
| Trust list | Danh sách các khóa công khai được tin, có đánh số phiên bản |
| Giai đoạn chồng lấn | Khoảng thời gian khóa cũ và khóa mới cùng được tin |
| Nonce | Số dùng một lần khi ký; tái sử dụng trong ECDSA làm lộ khóa riêng |
| Kiểm thử âm | Ca kiểm thử mà kết quả đúng là **thất bại** (phát hiện được gian lận) |

### 1.4. Tác nhân

| Tác nhân | Mô tả | Thao tác chính |
| --- | --- | --- |
| Người phát hành | Người tạo và ký artifact | Sinh khóa, tạo manifest, ký, luân chuyển khóa |
| Người tiêu thụ | Người tải artifact về và kiểm tra | Xác minh chữ ký, đọc lý do khi thất bại |
| Quản trị khóa | Người xử lý sự cố khóa | Thu hồi khóa, phát hành trust list mới, ký lại |
| Người đánh giá | Thành viên nhóm chạy thực nghiệm | Chạy benchmark, chạy bộ kiểm thử, xuất báo cáo |

---

## 2. Yêu cầu chức năng

Mỗi yêu cầu có mã **FR-xx**, mức ưu tiên (Bắt buộc / Nên có / Tùy chọn) và
liên kết tới minh chứng bắt buộc của đề bài (MH-01…MH-06 theo đề tài, ở đây
dùng ký hiệu của đề tài 19).

### 2.1. Quản lý khóa

| Mã | Yêu cầu | Ưu tiên | Minh chứng |
| --- | --- | --- | --- |
| FR-01 | Sinh cặp khóa cho RSA-PSS (2048 và 3072 bit), ECDSA (P-256) và Ed25519 | Bắt buộc | Khóa thử nghiệm |
| FR-02 | Tính và hiển thị dấu vân tay SHA-256 của khóa công khai | Bắt buộc | Dấu vân tay công khai |
| FR-03 | Lưu khóa riêng ở dạng tệp PEM có quyền truy cập hạn chế, tách khỏi khóa công khai | Bắt buộc | Cấu trúc thư mục `keys/` |
| FR-04 | Đăng ký khóa vào cơ sở dữ liệu kèm thuật toán, thời điểm tạo, hạn dùng, trạng thái | Bắt buộc | Bảng `key_pair` |

### 2.2. Manifest và ký

| Mã | Yêu cầu | Ưu tiên | Minh chứng |
| --- | --- | --- | --- |
| FR-05 | Tạo manifest gồm tên file, kích thước, SHA-256, số phiên bản manifest và định danh khóa ký | Bắt buộc | Manifest có phiên bản |
| FR-06 | Ký một artifact đơn lẻ bằng thuật toán chỉ định qua tham số `--alg` | Bắt buộc | Chữ ký |
| FR-07 | Ký manifest để bảo vệ cả bộ artifact bằng một chữ ký duy nhất | Bắt buộc | Chữ ký manifest |
| FR-08 | Gắn dấu thời gian vào chữ ký và lưu cùng chữ ký | Nên có | Token thời gian |
| FR-09 | Lưu chữ ký thành tệp tách rời (detached), không sửa artifact gốc | Bắt buộc | Thư mục `signatures/` |

### 2.3. Xác minh

| Mã | Yêu cầu | Ưu tiên | Minh chứng |
| --- | --- | --- | --- |
| FR-10 | Xác minh chữ ký của một artifact dựa trên trust list đang hiệu lực | Bắt buộc | Log xác minh |
| FR-11 | Khi xác minh thất bại, trả về **mã lý do** rõ ràng thay vì chỉ "sai" | Bắt buộc | Bảng mã lý do |
| FR-12 | Phát hiện và báo riêng ba loại sai lệch: nội dung file, metadata trong manifest, và chữ ký bị thay | Bắt buộc | Ca kiểm thử âm |
| FR-13 | Ghi mỗi lần xác minh vào nhật ký chỉ cho phép ghi thêm, dạng JSONL | Bắt buộc | `results/verify_log.jsonl` |
| FR-14 | Kiểm tra hạn dùng của khóa tại thời điểm ký, dựa trên dấu thời gian | Nên có | Ca kiểm thử dấu thời gian |

**Bảng mã lý do thất bại (FR-11):**

| Mã | Ý nghĩa |
| --- | --- |
| `OK` | Xác minh thành công |
| `SIG_INVALID` | Chữ ký không khớp với nội dung |
| `CONTENT_MODIFIED` | Mã băm nội dung khác với mã băm trong manifest |
| `METADATA_MODIFIED` | Trường metadata được bảo vệ đã bị sửa |
| `KEY_UNKNOWN` | Khóa ký không có trong trust list |
| `KEY_REVOKED` | Khóa đã bị thu hồi trước thời điểm ký |
| `KEY_EXPIRED` | Khóa hết hạn tại thời điểm ký |
| `TIMESTAMP_INVALID` | Dấu thời gian sai hoặc không kiểm chứng được |
| `MANIFEST_VERSION_MISMATCH` | Phiên bản manifest không khớp |

### 2.4. Vòng đời khóa

| Mã | Yêu cầu | Ưu tiên | Minh chứng |
| --- | --- | --- | --- |
| FR-15 | Tạo trust list mới có đánh số phiên bản, ghi rõ khóa nào hiệu lực từ bao giờ đến bao giờ | Bắt buộc | `trust_list_v*.json` |
| FR-16 | Luân chuyển khóa với giai đoạn chồng lấn cấu hình được, mặc định 14 ngày | Bắt buộc | Ca kiểm thử luân chuyển |
| FR-17 | Thu hồi khóa, ghi thời điểm và lý do | Bắt buộc | Bảng `revocation` |
| FR-18 | Liệt kê mọi artifact đã ký bằng khóa bị thu hồi | Bắt buộc | Runbook khóa bị lộ |
| FR-19 | Ký lại hàng loạt các artifact bị ảnh hưởng bằng khóa mới | Nên có | Log ký lại |

### 2.5. Đo lường và báo cáo

| Mã | Yêu cầu | Ưu tiên | Minh chứng |
| --- | --- | --- | --- |
| FR-20 | Đo thời gian ký và xác minh, lặp tối thiểu 100 lần cho mỗi thuật toán | Bắt buộc | `results/bench.csv` |
| FR-21 | Ghi kèm kích thước khóa và kích thước chữ ký vào kết quả đo | Bắt buộc | `results/bench.csv` |
| FR-22 | Xuất bảng truy vết minh chứng: mã minh chứng, phép thử, kết quả mong đợi, kết quả thực tế, tệp liên quan, thành viên phụ trách | Bắt buộc | `results/traceability.csv` |
| FR-23 | Cung cấp một giao diện dòng lệnh thống nhất cho mọi chức năng trên | Bắt buộc | `README.md` |

---

## 3. Yêu cầu phi chức năng

| Mã | Loại | Yêu cầu | Cách kiểm chứng |
| --- | --- | --- | --- |
| NFR-01 | Hiệu năng | Xác minh một artifact 1 MB hoàn tất dưới 50 ms trên máy lab, tính theo trung vị | Đọc `bench.csv` |
| NFR-02 | Đo lường | Mỗi phép đo lặp tối thiểu 100 lần; báo cáo trung vị và phân vị 95, không báo giá trị đơn lẻ | Kiểm tra số dòng trong `bench.csv` |
| NFR-03 | Khả năng tái lập | Chạy lại trên máy khác cho cùng kết luận; seed, phiên bản thư viện và phiên bản Python ghi trong README | Thành viên khác clone và chạy lại |
| NFR-04 | An toàn khóa | Khóa riêng không bao giờ được commit; `.gitignore` chặn `keys/**/*.key`; khóa riêng đặt quyền 600 | Kiểm tra `git log` và quyền tệp |
| NFR-05 | An toàn nhật ký | Nhật ký xác minh chỉ ghi thêm, không sửa dòng cũ | Kiểm thử ghi đè phải thất bại |
| NFR-06 | Bảo mật dữ liệu | Không ghi khóa riêng, nonce hay dữ liệu nhạy cảm vào log hoặc thông báo lỗi | Rà `verify_log.jsonl` |
| NFR-07 | Khả dụng | Mọi thông báo lỗi bằng tiếng Việt, nêu mã lý do và gợi ý bước tiếp theo | Rà thủ công toàn bộ mã lý do |
| NFR-08 | Tính di động | Chạy được trên Python 3.11 trở lên, trên Linux và Windows | Chạy thử trên hai hệ điều hành |
| NFR-09 | Chất lượng mã | Mọi hàm công khai có type hint và docstring; độ phủ kiểm thử từ 70% trở lên | `pytest --cov` |
| NFR-10 | Khả năng kiểm toán | Mỗi kết quả trong báo cáo truy được về một dòng dữ liệu hoặc một ca kiểm thử cụ thể | Bảng truy vết |
| NFR-11 | Đạo đức và pháp lý | Chỉ dùng khóa thử nghiệm; không ký phần mềm thật; mọi phép thử chạy trong sandbox do nhóm kiểm soát | Tuyên bố trong README |
| NFR-12 | Tài liệu | README có lệnh cài đặt, lệnh chạy, phiên bản công cụ và quy trình hoàn nguyên | Thành viên mới làm theo được |

---

## 4. Ràng buộc

- Ngôn ngữ: Python 3.11 trở lên. Thư viện mật mã: `cryptography`.
  Không tự cài đặt lại thuật toán mật mã.
- Cơ sở dữ liệu: SQLite, một tệp `data/sigtool.db`, để nhóm nộp kèm được.
- Toàn bộ dữ liệu là giả lập. Không dùng dữ liệu thật của bất kỳ tổ chức nào.
- Thời lượng 7 tuần, đề cương nộp tuần 1.

---

## 5. Giả định và rủi ro

| | Nội dung | Ảnh hưởng nếu sai |
| --- | --- | --- |
| Giả định 1 | Máy lab đủ ổn định để đo thời gian có ý nghĩa | Số liệu nhiễu, phải tăng số lần lặp |
| Giả định 2 | Dấu thời gian mô phỏng cục bộ được chấp nhận trong phạm vi đồ án | Phải tích hợp dịch vụ TSA thật, tốn thêm thời gian |
| Rủi ro 1 | Nhóm sa đà vào tối ưu hiệu năng thay vì vào kiểm thử âm | Mất điểm phần thực nghiệm, vốn chiếm 20 điểm |
| Rủi ro 2 | Khóa riêng lỡ bị commit | Phải xóa lịch sử Git và sinh lại toàn bộ khóa |
| Rủi ro 3 | Một thành viên làm hết phần kỹ thuật | Mất điểm đóng góp, đề yêu cầu cả ba cùng tham gia |
