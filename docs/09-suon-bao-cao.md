# Sườn báo cáo 25–35 trang

Đề bài yêu cầu cấu trúc: vấn đề, lý thuyết, thiết kế, thực nghiệm, kết quả,
thảo luận, giới hạn, kết luận và tài liệu tham khảo IEEE. Dưới đây là dàn ý
đã phân bổ số trang và gán người viết.

Số trang là gợi ý để không ai viết lan man. Tổng 29 trang, nằm giữa khung
25–35, còn chỗ co giãn.

| Mục | Nội dung | Trang | Người viết | Lấy từ |
| --- | --- | ---: | --- | --- |
| Bìa, mục lục | | 2 | Uyên | |
| **1. Đặt vấn đề** | Bài toán ký phần mềm, vì sao cần; ba câu hỏi nghiên cứu; phạm vi và giả định | 3 | Long | `docs/00`, `docs/01` |
| **2. Cơ sở lý thuyết** | | **7** | | |
| 2.1 | Chữ ký số: mô hình, toàn vẹn, xác thực nguồn gốc | 1,5 | Long | Chương 4 mục 4.5 |
| 2.2 | RSA-PSS: cấu trúc, vai trò của đệm, vì sao muối ngẫu nhiên không làm lộ khóa | 1,5 | Uyên | |
| 2.3 | ECDSA: đường cong P-256 và **hiểm họa tái sử dụng nonce** | 1,5 | Long | Chương 4 |
| 2.4 | EdDSA/Ed25519: nonce tất định `k = H(prefix‖M)` | 1 | Long | Chương 4 |
| 2.5 | Hàm băm, manifest, chuẩn hóa byte trước khi ký | 1 | Phiêu | |
| 2.6 | Dấu vân tay khóa, trust list, vòng đời khóa ký | 0,5 | Long | mục 4.8 |
| **3. Thiết kế hệ thống** | | **6** | | |
| 3.1 | Kiến trúc ba tầng, lý do tách tầng | 1 | Uyên | `docs/03` |
| 3.2 | Sơ đồ lớp, giao diện `Signer` và ba cài đặt | 1,5 | Long | `docs/03` |
| 3.3 | Mô hình dữ liệu, sơ đồ ERD | 1,5 | Phiêu | `docs/02` |
| 3.4 | Luồng ký và luồng xác minh, **thứ tự kiểm tra** | 1 | Long | `docs/03` |
| 3.5 | Mô hình đe dọa | 1 | Phiêu | `docs/05` |
| **4. Thực nghiệm** | | **5** | | |
| 4.1 | Môi trường, phiên bản công cụ, cách tái lập | 0,5 | Uyên | README |
| 4.2 | **Baseline** và lý do đo ở hai kích thước dữ liệu | 1 | Uyên | `docs/07` mục 1 |
| 4.3 | Thiết kế bộ kiểm thử: ca dương, ca âm, tiêu chí chấp nhận | 2 | Phiêu | `docs/04` |
| 4.4 | Kịch bản luân chuyển khóa và khóa bị lộ | 1,5 | Long | `docs/06` |
| **5. Kết quả** | | **5** | | |
| 5.1 | Bảng so sánh định lượng ba thuật toán, biểu đồ | 2 | Uyên | `docs/07` mục 2 |
| 5.2 | Bốn điều số liệu nói ra | 1,5 | Uyên | `docs/07` mục 3 |
| 5.3 | Kết quả phát hiện sai lệch, bảng mã lý do | 1 | Phiêu | `docs/07` mục 5 |
| 5.4 | Quan sát về nonce tất định | 0,5 | Long | `docs/07` mục 6 |
| **6. Thảo luận** | Ý nghĩa thực tế: ký một lần, xác minh nhiều lần; chọn thuật toán theo bối cảnh | 2 | Long | |
| **7. Giới hạn** | Giới hạn số liệu; **giới hạn của chống chối bỏ**; dấu thời gian mô phỏng; trust list do người quản | 2 | Long | `docs/05` mục 4, `docs/07` mục 7 |
| **8. Kết luận và hướng phát triển** | Trả lời ba câu hỏi nghiên cứu; hướng mở rộng sang PKI đầy đủ, HSM, Sigstore | 1,5 | Long | |
| **9. Tài liệu tham khảo** | Theo chuẩn IEEE | 1 | Uyên | |
| **Phụ lục** | Bảng truy vết minh chứng, bảng công khai AI, trích đoạn mã | ngoài đếm | Uyên | |

## Lưu ý khi viết

**Mục 2 là lý thuyết, không phải chép định nghĩa.** Mỗi tiểu mục phải nối
được với một quyết định thiết kế ở mục 3 hoặc một kết quả ở mục 5. Viết về
nonce tất định mà không dẫn tới quan sát "hai chữ ký giống hệt nhau" ở mục
5.4 là viết thừa.

**Mục 5 chỉ trình bày số liệu, không giải thích dài.** Phần giải thích để
dành cho mục 6.

**Mục 7 là chỗ ăn điểm.** Thang điểm có 10 điểm cho phân tích và giới hạn.
Nói rõ công cụ không bảo vệ được gì thì được điểm, giấu đi thì mất.

**Trích dẫn IEEE:** đánh số `[1]`, `[2]` theo thứ tự xuất hiện. Tối thiểu nên
có bài giảng Chương 4, RFC 8032 cho Ed25519, FIPS 186-5 cho ECDSA, RFC 8017
cho RSA-PSS, và tài liệu chính thức của thư viện `cryptography`.
