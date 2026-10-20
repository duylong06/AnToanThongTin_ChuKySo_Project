# Kế hoạch kiểm thử

Đề bài yêu cầu báo cả kết quả không như kỳ vọng. Một ca trượt có phân tích
được điểm cao hơn mười ca đều đạt mà không ai kiểm chứng được.

## 1. Nguyên tắc

- Mỗi ca có **kết quả mong đợi viết ra trước khi chạy**. Viết sau là tự huyễn hoặc.
- Ca âm phải phân biệt được bằng **mã lý do**, không chỉ "thất bại".
- Mỗi ca để lại một tệp minh chứng truy được: dòng trong `verify_log.jsonl`
  hoặc dòng trong `bench.csv`.
- Chạy lại toàn bộ bằng một lệnh: `pytest -q`.

## 2. Danh sách ca kiểm thử

| Mã | Loại | Nội dung | Kết quả mong đợi | Minh chứng | Người |
| --- | --- | --- | --- | --- | --- |
| TC-01 | Dương | Ký rồi xác minh, lần lượt ba thuật toán | `OK` | `verify_log.jsonl` | B |
| TC-02 | Dương | Ký manifest, xác minh cả bộ artifact | `OK` | `verify_log.jsonl` | B |
| TC-03 | Âm | Sửa một byte trong nội dung tệp | `CONTENT_MODIFIED` | `verify_log.jsonl` | B |
| TC-04 | Âm | Sửa một trường metadata trong manifest | `METADATA_MODIFIED` | `verify_log.jsonl` | B |
| TC-05 | Âm | Thay chữ ký bằng chữ ký của tệp khác | `SIG_INVALID` | `verify_log.jsonl` | B |
| TC-06 | Âm | Ký bằng khóa không có trong trust list | `KEY_UNKNOWN` | `verify_log.jsonl` | B |
| TC-07 | Dương | Xác minh chữ ký khóa cũ trong giai đoạn chồng lấn | `OK` | `verify_log.jsonl` | C |
| TC-08 | Âm | Xác minh chữ ký khóa cũ sau khi hết chồng lấn | `KEY_EXPIRED` | `verify_log.jsonl` | C |
| TC-09 | Âm | Chữ ký tạo sau thời điểm khóa bị thu hồi | `KEY_REVOKED` | `verify_log.jsonl` | C |
| TC-10 | Dương | Liệt kê artifact bị ảnh hưởng khi khóa bị lộ | Đúng số lượng | Ảnh chụp kết quả lệnh | C |
| TC-11 | Dương | Benchmark lặp 100 lần mỗi thuật toán | 600 dòng dữ liệu | `bench.csv` | A |
| TC-12 | Âm | Ghi đè một dòng cũ trong nhật ký | Thao tác bị từ chối | Thông báo lỗi | B |

## 3. Chỉ số cần đạt

| Chỉ số | Ngưỡng | Nguồn |
| --- | --- | --- |
| Tỷ lệ ca kiểm thử đạt | 12/12, hoặc giải thích rõ ca trượt | `pytest` |
| Độ phủ mã | Từ 70% trở lên | `pytest --cov` |
| Thời gian xác minh, trung vị | Dưới 50 ms với tệp 1 MB | `bench.csv` |
| Số lần lặp mỗi phép đo | Tối thiểu 100 | `bench.csv` |

## 4. Bảng truy vết minh chứng

Xuất ra `results/traceability.csv`, nộp kèm báo cáo. Mỗi dòng nối một ca
kiểm thử với yêu cầu mà nó chứng minh:

```csv
ma_minh_chung,yeu_cau,phep_thu,ket_qua_mong_doi,ket_qua_thuc_te,tep_lien_quan,thanh_vien
TC-03,FR-12,Sua mot byte noi dung,CONTENT_MODIFIED,,results/verify_log.jsonl,B
TC-08,FR-16,Het giai doan chong lan,KEY_EXPIRED,,results/verify_log.jsonl,C
```

Cột `ket_qua_thuc_te` để trống đến khi chạy thật. Không điền trước.
