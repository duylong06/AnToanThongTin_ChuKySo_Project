# Mô hình đe dọa

Phần này trả lời: công cụ bảo vệ cái gì, trước ai, và **không** bảo vệ được gì.
Mục cuối quan trọng nhất khi chấm phần phân tích giới hạn.

## 1. Tài sản cần bảo vệ

| Tài sản | Vì sao có giá trị | Hậu quả nếu mất |
| --- | --- | --- |
| Khóa riêng của người phát hành | Ký được bất cứ thứ gì dưới danh nghĩa họ | Kẻ tấn công phát tán mã độc có chữ ký hợp lệ |
| Tính toàn vẹn của artifact | Người dùng tin và chạy nó | Mã độc chạy với quyền của người dùng |
| Trust list | Quyết định khóa nào được tin | Thêm khóa của kẻ tấn công vào là xong |
| Nhật ký xác minh | Bằng chứng kiểm toán | Không truy được sự cố đã xảy ra thế nào |

## 2. Kẻ tấn công và năng lực giả định

| Kẻ tấn công | Năng lực | Mục tiêu |
| --- | --- | --- |
| Kẻ xen giữa | Sửa tệp trên đường truyền, không có khóa riêng | Chèn mã độc vào bản tải về |
| Người trong nội bộ | Đọc được thư mục chứa khóa | Ký trái phép |
| Kẻ khai thác lỗi cài đặt | Quan sát nhiều chữ ký ECDSA | Khôi phục khóa riêng từ nonce lặp |
| Người dùng cẩu thả | Bỏ qua cảnh báo xác minh | Tự làm hại mình |

## 3. Đe dọa và biện pháp

| Đe dọa | Biện pháp trong công cụ | Ca kiểm thử |
| --- | --- | --- |
| Sửa nội dung artifact | Băm SHA-256 và chữ ký trên manifest | TC-03 |
| Sửa metadata để lách | Metadata nằm trong phần được ký | TC-04 |
| Dùng lại chữ ký của tệp khác | Chữ ký gắn với mã băm cụ thể | TC-05 |
| Khóa lạ mạo danh | Trust list có phiên bản | TC-06 |
| Khóa bị lộ | Thu hồi, ký lại, cảnh báo | TC-09, runbook |
| Nonce lặp trong ECDSA | Dùng thư viện chuẩn, không tự cài đặt; nêu rõ Ed25519 sinh nonce tất định | Phân tích trong báo cáo |
| Chữ ký cũ sau khi chứng thư hết hạn | Dấu thời gian | TC-07, TC-08 |

## 4. Điều công cụ KHÔNG bảo vệ được

Đây là phần đáng viết nhất.

- **Chữ ký chứng minh khóa đã ký, không chứng minh con người đã ký.**
  Nếu máy của người phát hành bị chiếm quyền, mọi chữ ký tạo ra đều hợp lệ
  về mặt mật mã. Khái niệm chống chối bỏ sụp đổ ở đúng chỗ này.
- **Trust list do con người quản.** Ai thêm được khóa vào trust list thì
  người đó thắng, không cần phá mật mã.
- **Công cụ không nói artifact có an toàn hay không.** Nó chỉ nói artifact
  đúng là bản mà người giữ khóa đó đã ký. Mã độc được ký hợp lệ vẫn là mã độc.
- **Dấu thời gian trong đồ án là mô phỏng cục bộ**, không phải dịch vụ TSA
  độc lập. Một TSA thật mới có giá trị trước bên thứ ba.
- **Khóa thử nghiệm nằm trên cùng máy chạy công cụ.** Môi trường thật phải
  dùng HSM hoặc dịch vụ quản lý khóa, nằm ngoài phạm vi đồ án.
