# Runbook: xử lý khi khóa ký bị lộ

Tài liệu vận hành, viết ở dạng các bước làm được ngay. Đây là một trong bốn
kết quả thực nghiệm đề bài yêu cầu.

**Điều kiện kích hoạt:** nghi ngờ hoặc xác nhận khóa riêng đã ra ngoài tầm
kiểm soát — máy bị xâm nhập, tệp khóa bị sao chép, khóa lỡ bị commit lên Git.

## Giờ đầu tiên

1. **Dừng ký.** Chuyển trạng thái khóa sang `revoked` trong cơ sở dữ liệu.
   Mọi lệnh ký bằng khóa này phải thất bại ngay.
   ```bash
   python -m dt19 revoke --key <key_id> --reason "khoa bi lo"
   ```
2. **Ghi lại thời điểm nghi ngờ bị lộ**, không phải thời điểm phát hiện.
   Hai mốc này thường cách nhau khá xa, và mốc đầu mới là mốc dùng để
   phân loại chữ ký nào còn đáng tin.
3. **Đừng xóa gì cả.** Nhật ký và chữ ký cũ là bằng chứng.

## Xác định thiệt hại

4. Liệt kê toàn bộ artifact đã ký bằng khóa đó:
   ```bash
   python -m dt19 affected --key <key_id>
   ```
5. Chia làm hai nhóm theo mốc ở bước 2:
   - Ký **trước** thời điểm nghi ngờ bị lộ: nhiều khả năng vẫn hợp lệ,
     nếu có dấu thời gian kiểm chứng được.
   - Ký **sau** thời điểm đó: coi như không đáng tin, bất kể xác minh có đạt.
6. Ghi số lượng mỗi nhóm vào bảng `revocation.affected_signatures`.

## Khôi phục

7. Sinh khóa mới, **thuật toán khác hoặc cùng thuật toán đều được**, nhưng
   phải là cặp khóa hoàn toàn mới:
   ```bash
   python -m dt19 keygen --alg ed25519 --owner <ten>
   ```
8. Phát hành trust list phiên bản mới: thêm khóa mới, đánh dấu khóa cũ
   hết hiệu lực **tại thời điểm nghi ngờ bị lộ**, không phải hôm nay.
9. Ký lại nhóm artifact bị ảnh hưởng:
   ```bash
   python -m dt19 resign --old <key_id_cu> --new <key_id_moi>
   ```
10. Công bố trust list mới và thông báo cho người dùng, kèm dấu vân tay
    khóa mới để họ đối chiếu.

## Sau sự cố

11. Viết lại dòng thời gian: lộ lúc nào, phát hiện lúc nào, dừng ký lúc nào,
    khôi phục xong lúc nào. Khoảng cách giữa các mốc chính là chỉ số cần cải thiện.
12. Trả lời: vì sao khóa lọt ra? Biện pháp nào đáng lẽ đã chặn được?
13. Nếu khóa lọt qua Git, xóa khỏi lịch sử chưa đủ — **coi như đã lộ vĩnh viễn**
    và vẫn phải làm toàn bộ quy trình trên.

## Chỉ số đo được của quy trình này

| Chỉ số | Cách đo | Mục tiêu trong đồ án |
| --- | --- | --- |
| Thời gian từ phát hiện đến dừng ký | Hiệu hai mốc trong `revocation` | Dưới 15 phút |
| Số artifact bị ảnh hưởng xác định đúng | So với số thật trong kịch bản mô phỏng | Đúng 100% |
| Thời gian khôi phục hoàn toàn | Đến khi trust list mới công bố | Dưới 1 giờ |
