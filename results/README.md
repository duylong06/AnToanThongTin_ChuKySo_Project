# Thư mục kết quả

Các tệp trong đây do công cụ sinh ra, không commit (xem `.gitignore`).
Khi nộp bài thì nén cả thư mục này kèm báo cáo.

| Tệp | Nội dung | Yêu cầu liên quan |
| --- | --- | --- |
| `bench.csv` | Từng lần đo thời gian ký và xác minh | FR-20, FR-21, NFR-02 |
| `verify_log.jsonl` | Nhật ký xác minh, chỉ ghi thêm | FR-13, NFR-05 |
| `traceability.csv` | Bảng truy vết minh chứng | FR-22, NFR-10 |

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
