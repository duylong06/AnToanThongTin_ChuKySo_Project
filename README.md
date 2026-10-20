# dt19 — sigtool

Công cụ ký và xác minh artifact bằng RSA-PSS, ECDSA và Ed25519.
Đồ án **Đề tài 19 — Đánh giá chữ ký số cho phần mềm và tài liệu điện tử**,
học phần An toàn thông tin (123033), Trường Đại học Giao thông Vận tải TP.HCM.
Giảng viên hướng dẫn: TS. Lê Quốc Tuấn.

> **Khóa trong kho này là khóa thử nghiệm, chỉ dùng cho đồ án.**
> Không ký phần mềm thật bằng danh tính hoặc chứng thư của bất kỳ tổ chức nào.
> Mọi phép thử chạy trong môi trường do nhóm kiểm soát, trên dữ liệu giả lập.

## Thành viên

| | Họ và tên | MSSV | Phần chịu trách nhiệm |
| --- | --- | --- | --- |
| 1 | **Nguyễn Duy Long** | 060206005525 | Lõi mật mã, xác minh, vòng đời khóa |
| 2 | Nguyễn Quỳnh Phiêu | *(điền MSSV)* | Manifest, lưu trữ, kiểm thử âm |
| 3 | Trương Hồng Uyên | *(điền MSSV)* | Đo lường, dòng lệnh, báo cáo |

Phân công chi tiết theo tuần: [docs/08-phan-cong-va-tien-do.md](docs/08-phan-cong-va-tien-do.md)

## Trạng thái

| | |
| --- | --- |
| Ca kiểm thử | **22/22 đạt** |
| Độ phủ mã | **94%** (ngưỡng đặt ra: 70%) |
| Xác minh tệp 1 MB | **2,73 ms** (ngưỡng: dưới 50 ms) |
| Số loại sai lệch phân biệt được | **7** mã lý do riêng |

## Tài liệu

| Tệp | Nội dung |
| --- | --- |
| [00-de-cuong.md](docs/00-de-cuong.md) | Phiếu đề cương nộp tuần 1, có ô duyệt của giảng viên |
| [01-dac-ta-yeu-cau.md](docs/01-dac-ta-yeu-cau.md) | 23 yêu cầu chức năng, 12 yêu cầu phi chức năng, bảng mã lý do |
| [02-mo-hinh-du-lieu-erd.md](docs/02-mo-hinh-du-lieu-erd.md) | Sơ đồ ERD và lý do thiết kế từng bảng |
| [03-so-do-lop.md](docs/03-so-do-lop.md) | Sơ đồ lớp, phân tầng, luồng ký và luồng xác minh |
| [04-ke-hoach-kiem-thu.md](docs/04-ke-hoach-kiem-thu.md) | Ca kiểm thử có kết quả mong đợi viết trước |
| [05-mo-hinh-de-doa.md](docs/05-mo-hinh-de-doa.md) | Tài sản, kẻ tấn công, điều công cụ không bảo vệ được |
| [06-runbook-khoa-bi-lo.md](docs/06-runbook-khoa-bi-lo.md) | Quy trình xử lý khi khóa ký bị lộ |
| [07-ket-qua-thuc-nghiem.md](docs/07-ket-qua-thuc-nghiem.md) | Baseline, số liệu đo thật, biểu đồ, phân tích |
| [08-phan-cong-va-tien-do.md](docs/08-phan-cong-va-tien-do.md) | Ai làm gì, tuần nào, minh chứng là gì |
| [09-suon-bao-cao.md](docs/09-suon-bao-cao.md) | Dàn ý báo cáo 25–35 trang, phân bổ trang và người viết |

## Môi trường

| Thành phần | Phiên bản |
| --- | --- |
| Python | 3.11 trở lên (đã chạy trên 3.13.16) |
| cryptography | 43.0.1 trở lên (đã chạy trên 50.0.1) |
| pytest | 8.3.3 trở lên |

Ghi lại phiên bản thực tế của máy mình bằng `python -V` và `pip freeze` rồi
dán vào báo cáo. Đề bài yêu cầu ghi phiên bản công cụ.

## Cài đặt

```bash
git clone https://github.com/duylong06/AnToanThongTin_ChuKySo_Project.git
cd AnToanThongTin_ChuKySo_Project
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export PYTHONPATH=src            # Windows: set PYTHONPATH=src
python -m dt19 init
```

## Dùng thử trong năm phút

```bash
# 1. Sinh khóa Ed25519, tự động tạo trust list phiên bản 1
python -m dt19 keygen --alg ed25519 --owner "Nguyen Duy Long"
python -m dt19 keys                      # xem mã khóa vừa sinh

# 2. Lập manifest cho thư mục artifacts
python -m dt19 manifest --dir artifacts --out artifacts/manifest.json

# 3. Ký manifest bằng khóa vừa sinh
python -m dt19 sign artifacts/manifest.json --key <key_id> --manifest

# 4. Xác minh — phải ra [DAT] OK
python -m dt19 verify artifacts/manifest.json --sig <signature_id>

# 5. Thử phá: sửa một byte rồi xác minh lại — phải ra CONTENT_MODIFIED
python -c "p='artifacts/app.bin';d=bytearray(open(p,'rb').read());d[0]^=1;open(p,'wb').write(d)"
python -m dt19 verify artifacts/manifest.json --sig <signature_id>
```

Các lệnh còn lại:

```bash
python -m dt19 rotate   --old <key_cu> --new <key_moi> --overlap-days 14
python -m dt19 revoke   --key <key_id> --reason "khoa bi lo" [--since 2026-10-15T08:00]
python -m dt19 affected --key <key_id>
python -m dt19 bench    --iterations 100 --size 1048576
```

## Kiểm thử

```bash
pytest -q --cov=src/dt19 --cov-report=term-missing
```

Ca kiểm thử âm quan trọng hơn ca dương: chúng chứng minh rằng mọi sửa đổi đều
bị phát hiện, và phát hiện **đúng nguyên nhân**. Xem `tests/test_tamper.py`.

## Tái lập kết quả đo

1. Dùng đúng phiên bản thư viện trong `requirements.txt`.
2. Chạy benchmark ở cả hai kích thước:
   ```bash
   python -m dt19 bench --iterations 100 --size 1048576 --out results/bench.csv
   python -m dt19 bench --iterations 100 --size 1024    --out results/bench_1kb.csv
   ```
3. So **trung vị**, không so giá trị đơn lẻ. Máy khác cho con số khác, nhưng
   thứ tự giữa ba thuật toán phải giữ nguyên — đó mới là kết luận.

## Hoàn nguyên

```bash
rm -f data/sigtool.db results/verify_log.jsonl
rm -rf keys/ signatures/
python -m dt19 init
```

## Công khai sử dụng AI

| Công cụ | Nội dung hỗ trợ | Phần nhóm tự chịu trách nhiệm |
| --- | --- | --- |
| *(điền tên công cụ)* | *(điền: gợi ý cấu trúc, hỗ trợ viết mã, soạn bản nháp tài liệu…)* | *(điền: rà soát lập luận, đối chiếu bài giảng, chạy lại toàn bộ kiểm thử, kiểm chứng số liệu)* |
