# Thư mục kết quả

Các tệp trong đây là minh chứng bắt buộc của đề bài nên ĐƯỢC commit.
Chạy lại công cụ sẽ ghi đè chúng bằng số liệu của máy bạn.

| Tệp | Nội dung | Yêu cầu liên quan |
| --- | --- | --- |
| `bench.csv` | Từng lần đo thời gian ký và xác minh | FR-20, FR-21, NFR-02 |
| `verify_log.jsonl` | Nhật ký xác minh, chỉ ghi thêm | FR-13, NFR-05 |
| `traceability.csv` | Bảng truy vết minh chứng | FR-22, NFR-10 |
| `bench_1kb.csv` | Đo với dữ liệu 1 KB để tách chi phí băm | FR-20 |
| `bieu_do_hieu_nang.png` | Biểu đồ so sánh ba thuật toán | Giai đoạn Đánh giá |

Cột của `bench.csv`:

```csv
alg,thao_tac,lan,kich_thuoc_khoa_byte,kich_thuoc_chu_ky_byte,thoi_gian_ms
ed25519,sign,1,32,64,0.08
ed25519,verify,1,32,64,0.19
```

Cột của `traceability.csv`:

```csv
ma_minh_chung,phep_thu,ket_qua_mong_doi,ket_qua_thuc_te,tep_lien_quan,thanh_vien
TC-03,Sua mot byte noi dung,CONTENT_MODIFIED,,results/verify_log.jsonl,B
```
