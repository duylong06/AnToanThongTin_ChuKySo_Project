# Phiếu đề cương đồ án — nộp tuần 1

**Học phần:** An toàn thông tin (123033) — TS. Lê Quốc Tuấn
**Đề tài 19:** Đánh giá chữ ký số cho phần mềm và tài liệu điện tử
**Bám sát mục:** 4.5, 4.7, 4.8 và 4.9.3 — **Mức độ:** Khá — **Thời lượng:** 7 tuần

## 1. Thành viên và phân công

| | Họ và tên | MSSV | Vai trò | Phần chịu trách nhiệm |
| --- | --- | --- | --- | --- |
| 1 | **Nguyễn Duy Long** | 060206005525 | Nhóm trưởng, phụ trách kỹ thuật | Lõi mật mã, xác minh, vòng đời khóa |
| 2 | Nguyễn Quỳnh Phiêu | *(điền MSSV)* | Thành viên | Manifest, lưu trữ, kiểm thử âm |
| 3 | Trương Hồng Uyên | *(điền MSSV)* | Thành viên | Đo lường, biểu đồ, báo cáo |

Cả ba cùng tham gia thiết kế, phân tích và bảo vệ. Chi tiết theo tuần ở
`docs/08-phan-cong-va-tien-do.md`.

## 2. Câu hỏi nghiên cứu

Nhóm đặt ba câu hỏi, mỗi câu trả lời được bằng số liệu hoặc bằng ca kiểm thử:

1. **Ba thuật toán RSA-PSS, ECDSA và Ed25519 khác nhau thế nào về kích thước
   chữ ký, tốc độ ký, tốc độ xác minh và yêu cầu nonce?**
   Trả lời bằng benchmark 100 lần lặp ở hai kích thước dữ liệu.

2. **Mọi thay đổi trên nội dung hoặc metadata được bảo vệ có thực sự làm xác
   minh thất bại không, và công cụ có phân biệt được nguyên nhân không?**
   Trả lời bằng bộ ca kiểm thử âm, mỗi ca một mã lý do riêng.

3. **Khi khóa ký bị lộ thì xử lý ra sao, và quy trình đó đo được bằng chỉ số
   nào?** Trả lời bằng kịch bản mô phỏng thu hồi và runbook có chỉ số.

## 3. Phạm vi

**Làm:** sinh và quản lý khóa thử nghiệm; tạo manifest có phiên bản; ký và
xác minh artifact lẫn manifest; dấu thời gian; trust list theo phiên bản;
luân chuyển khóa có giai đoạn chồng lấn; thu hồi khóa và ký lại; đo hiệu năng.

**Không làm:** hạ tầng khóa công khai đầy đủ với CA gốc và CA trung gian
(thuộc đề tài 20); giao diện đồ họa; dịch vụ dấu thời gian đạt chuẩn RFC 3161
của bên thứ ba; ký phần mềm thật bằng danh tính của bất kỳ tổ chức nào.

## 4. Kiến trúc

Công cụ dòng lệnh viết bằng Python, chia ba tầng với phụ thuộc một chiều:

- **Tầng miền** — `models.py`, `trust.py`: kiểu dữ liệu thuần, không biết đĩa.
- **Tầng nghiệp vụ** — `services.py`: ký, xác minh, thu hồi, đo.
- **Tầng hạ tầng** — `signers.py`, `repository.py`: thư viện mật mã, SQLite.

`Signer` là giao diện trừu tượng, ba thuật toán là ba cài đặt. Nhờ vậy thêm
thuật toán thứ tư không phải sửa tầng nghiệp vụ. Sơ đồ chi tiết ở
`docs/03-so-do-lop.md`.

## 5. Dữ liệu và môi trường

| Hạng mục | Lựa chọn |
| --- | --- |
| Dữ liệu | Hoàn toàn giả lập: một tệp nhị phân sinh ngẫu nhiên, một tài liệu văn bản, một manifest. Không dùng dữ liệu thật của bất kỳ tổ chức nào |
| Khóa | Khóa thử nghiệm sinh tại chỗ, chỉ dùng cho đồ án, không commit khóa riêng lên kho mã |
| Ngôn ngữ | Python 3.11 trở lên |
| Thư viện mật mã | `cryptography` — không tự cài đặt lại thuật toán |
| Lưu trữ | SQLite, một tệp `data/sigtool.db`, nộp kèm được |
| Môi trường chạy | Máy cá nhân của thành viên, trong môi trường ảo Python riêng |
| Kho mã | `github.com/duylong06/AnToanThongTin_ChuKySo_Project` |

## 6. Chỉ số đánh giá

| Mã | Chỉ số | Ngưỡng đặt ra |
| --- | --- | --- |
| CS-1 | Thời gian ký và xác minh, trung vị và phân vị 95 | Xác minh tệp 1 MB dưới 50 ms |
| CS-2 | Kích thước chữ ký và kích thước khóa | Ghi nhận, không đặt ngưỡng |
| CS-3 | Số lần lặp mỗi phép đo | Tối thiểu 100 |
| CS-4 | Tỷ lệ ca kiểm thử đạt | 100%, hoặc giải thích rõ ca trượt |
| CS-5 | Độ phủ kiểm thử | Từ 70% trở lên |
| CS-6 | Số loại sai lệch phân biệt được bằng mã lý do riêng | Tối thiểu 4 |
| CS-7 | Thời gian từ phát hiện khóa lộ đến dừng ký | Dưới 15 phút |

## 7. Điều kiện an toàn và đạo đức

- Khóa thử nghiệm **chỉ dùng cho đồ án**. Tuyệt đối không ký phần mềm thật
  bằng danh tính hoặc chứng thư của tổ chức nào.
- Khóa riêng không bao giờ được commit. `.gitignore` chặn, và quy trình CI
  có bước kiểm tra tự động, hỏng build nếu phát hiện.
- Mọi phép thử chạy trên dữ liệu giả lập do nhóm tự tạo.
- Không tấn công hay dò quét bất kỳ hệ thống nào ngoài máy của nhóm.
- Phiên bản công cụ ghi đầy đủ trong README để người khác tái lập được.

## 8. Sản phẩm cam kết nộp

Báo cáo 25–35 trang trích dẫn IEEE; kho mã nguồn có README đầy đủ; công cụ ký
và xác minh chạy được; bảng so sánh định lượng ba thuật toán; manifest có
phiên bản và định danh khóa; runbook xử lý khóa bị lộ; bộ artifact gốc và bản
bị sửa; khóa thử nghiệm kèm dấu vân tay; chữ ký và log xác minh; tệp
benchmark; sơ đồ vòng đời khóa ký; bảng truy vết minh chứng; bảng công khai
việc sử dụng AI.

---

**Ý kiến của giảng viên:**

&nbsp;

&nbsp;

☐ Đồng ý phê duyệt &nbsp;&nbsp; ☐ Yêu cầu chỉnh sửa &nbsp;&nbsp; ☐ Không đồng ý

Ngày ..... tháng ..... năm 2026
