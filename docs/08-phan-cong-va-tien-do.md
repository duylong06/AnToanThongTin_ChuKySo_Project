# Phân công và tiến độ theo tuần

Tài liệu này để chia việc và theo dõi commit. Mỗi tuần có đầu ra cụ thể,
mỗi đầu ra có người chịu trách nhiệm rõ ràng.

## 1. Nguyên tắc chia việc

Đề bài ghi rõ: *"Cả ba phải tham gia thiết kế, thực nghiệm, phân tích và bảo
vệ; không chia tách theo kiểu một người chỉ viết báo cáo."*

Vì vậy nhóm chia theo **lát dọc**, không chia theo tầng. Mỗi người sở hữu một
nhóm chức năng từ mã nguồn, qua kiểm thử, đến phần lý thuyết tương ứng trong
báo cáo. Như vậy ai cũng chạm vào cả ba loại việc, và khi bảo vệ thì ai cũng
trả lời được về phần mình.

## 2. Phân công theo người

### Nguyễn Duy Long — 060206005525 — phần khó nhất

Sở hữu toàn bộ phần mật mã và vòng đời khóa. Đây là phần nhiều rủi ro kỹ
thuật nhất, vì sai một chi tiết nhỏ là cả hệ thống mất giá trị bảo vệ.

| Hạng mục | Tệp | Vì sao khó |
| --- | --- | --- |
| Giao diện `Signer` và ba cài đặt | `src/dt19/signers.py` | Phải thiết kế trừu tượng đúng để ba thuật toán khác nhau hoàn toàn vẫn dùng chung một giao diện |
| Logic xác minh và thứ tự kiểm tra | `src/dt19/services.py` | Thứ tự tra trust list, kiểm chữ ký, kiểm dấu thời gian quyết định mã lý do trả về có đúng hay không |
| Trust list và luân chuyển khóa | `src/dt19/trust.py` | Giai đoạn chồng lấn, khoảng hiệu lực theo thời điểm ký chứ không theo hiện tại |
| Thu hồi khóa và xử lý hậu quả | `src/dt19/services.py` | Phân loại chữ ký trước và sau mốc nghi ngờ bị lộ |
| Dấu thời gian | `src/dt19/services.py` | Phải tách được để kiểm thử bơm thời gian giả |
| Kiểm thử luân chuyển và thu hồi | `tests/test_rotation.py` | |

**Phần lý thuyết trình bày:** mô hình chữ ký số; EdDSA và cơ chế nonce tất
định; ECDSA và hiểm họa tái sử dụng nonce; vòng đời khóa; **giới hạn của khái
niệm chống chối bỏ** — phần này đáng giá nhất khi chấm.

### Nguyễn Quỳnh Phiêu — phần dữ liệu và kiểm thử âm

| Hạng mục | Tệp |
| --- | --- |
| Lớp miền, manifest, chuẩn hóa byte để ký | `src/dt19/models.py` |
| Tầng lưu trữ SQLite và bản trong bộ nhớ | `src/dt19/repository.py` |
| Lược đồ cơ sở dữ liệu | `data/schema.sql` |
| Toàn bộ ca kiểm thử âm | `tests/test_tamper.py` |
| Nhật ký xác minh chỉ ghi thêm | `src/dt19/services.py` phần `_log` |
| Sơ đồ ERD | `docs/02-mo-hinh-du-lieu-erd.md` |

**Phần lý thuyết trình bày:** tính toàn vẹn; hàm băm SHA-256; vì sao phải
chuẩn hóa byte trước khi ký; manifest và provenance.

### Trương Hồng Uyên — phần đo lường và hồ sơ

| Hạng mục | Tệp |
| --- | --- |
| Bộ đo hiệu năng và xuất CSV | `src/dt19/services.py` lớp `BenchmarkRunner` |
| Giao diện dòng lệnh | `src/dt19/cli.py` |
| Ca kiểm thử dương và kiểm thử dòng lệnh | `tests/test_positive.py`, `tests/test_cli.py` |
| Biểu đồ và bảng kết quả | `results/`, `docs/07-ket-qua-thuc-nghiem.md` |
| Bảng truy vết minh chứng | `results/traceability.csv` |
| Báo cáo và trình chiếu | `docs/09-suon-bao-cao.md` |

**Phần lý thuyết trình bày:** RSA-PSS và vai trò của đệm; tính bất đối xứng
giữa ký và xác minh; phương pháp đo và vì sao dùng trung vị thay vì trung bình.

## 3. Tiến độ theo tuần

Cột "Minh chứng" là thứ phải có mặt trong kho mã vào cuối tuần đó.

| Tuần | Giai đoạn | Việc | Người | Minh chứng |
| --- | --- | --- | --- | --- |
| **1** | Đề cương | Chốt câu hỏi nghiên cứu, phạm vi, chỉ số, phân công. Nộp phiếu đề cương | Long chủ trì, cả ba góp ý | `docs/00-de-cuong.md` có chữ ký duyệt |
| **1** | Đề cương | Dựng kho mã, cấu trúc thư mục, CI | Uyên | Kho mã chạy được `pytest` |
| **2** | Thiết kế | Mô hình đe dọa, kế hoạch kiểm thử, baseline | Long và Phiêu | `docs/05`, `docs/04`, mục baseline trong `docs/07` |
| **2** | Thiết kế | Sơ đồ lớp, sơ đồ ERD, lược đồ cơ sở dữ liệu | Phiêu | `docs/02`, `docs/03`, `data/schema.sql` |
| **3** | Triển khai | Lớp miền, manifest, chuẩn hóa byte | Phiêu | `models.py` + ca kiểm thử đạt |
| **3** | Triển khai | Giao diện `Signer` và Ed25519 chạy được vòng ký → xác minh | **Long** | `signers.py` + `test_positive.py` |
| **4** | Triển khai | Thêm ECDSA và RSA-PSS vào cùng giao diện | **Long** | Ba thuật toán cùng chạy |
| **4** | Triển khai | Tầng lưu trữ, nhật ký xác minh | Phiêu | `repository.py`, `verify_log.jsonl` |
| **4** | Triển khai | Giao diện dòng lệnh | Uyên | `cli.py` + `test_cli.py` |
| **5** | Đánh giá | Ca kiểm thử âm đủ bốn loại sai lệch | Phiêu | `test_tamper.py` đạt |
| **5** | Đánh giá | Luân chuyển khóa, thu hồi, runbook | **Long** | `trust.py`, `docs/06`, `test_rotation.py` |
| **5** | Đánh giá | Chạy benchmark, vẽ biểu đồ, lập bảng kết quả | Uyên | `bench.csv`, biểu đồ, `docs/07` |
| **6** | Bàn giao | Viết báo cáo 25–35 trang | Cả ba, mỗi người phần mình | `docs/09-suon-bao-cao.md` triển khai đầy đủ |
| **6** | Bàn giao | Bảng truy vết, hướng dẫn tái tạo, bảng công khai AI | Uyên | `results/traceability.csv`, README |
| **6** | Bàn giao | Tập bảo vệ, chuẩn bị demo | Cả ba | Bản trình chiếu |
| **7** | Dự phòng | Sửa theo góp ý của thầy, hoàn thiện | Cả ba | |

## 4. Quy ước commit

Để lịch sử commit thể hiện được đóng góp của từng người:

- Mỗi người commit bằng tài khoản GitHub của chính mình. Không ai commit hộ ai.
- Mỗi commit gắn với một yêu cầu: `[FR-06] Them ky artifact bang Ed25519`.
- Commit nhỏ và thường xuyên, đừng dồn cả tuần vào một commit lớn.
- Mã mới phải kèm ca kiểm thử trong cùng commit hoặc commit kế tiếp.
- Không commit khóa riêng. CI sẽ chặn, nhưng tốt nhất là đừng tạo ra tình huống đó.

## 5. Mốc kiểm tra chéo

Cuối mỗi tuần, nhóm họp ngắn và trả lời ba câu:

1. Tuần này có minh chứng nào mới vào kho mã chưa?
2. Có ca kiểm thử nào đang trượt mà chưa ai nhận xử lý không?
3. Ai đang bị kẹt, và cần ai hỗ trợ?

Ghi biên bản ngắn vào `docs/bien-ban/` để làm bằng chứng đóng góp khi bảo vệ.
