# dt19 — sigtool

Công cụ ký và xác minh artifact bằng RSA-PSS, ECDSA và Ed25519.
Đồ án **Đề tài 19 — Đánh giá chữ ký số cho phần mềm và tài liệu điện tử**,
học phần An toàn thông tin (123033), Trường Đại học Giao thông Vận tải TP.HCM.

> **Khóa trong kho này là khóa thử nghiệm, chỉ dùng cho đồ án.**
> Không ký phần mềm thật bằng danh tính hoặc chứng thư của bất kỳ tổ chức nào.
> Mọi phép thử chạy trong môi trường do nhóm kiểm soát, trên dữ liệu giả lập.

## Tài liệu

| Tệp | Nội dung |
| --- | --- |
| [docs/01-dac-ta-yeu-cau.md](docs/01-dac-ta-yeu-cau.md) | Phạm vi, tác nhân, 23 yêu cầu chức năng, 12 yêu cầu phi chức năng |
| [docs/02-mo-hinh-du-lieu-erd.md](docs/02-mo-hinh-du-lieu-erd.md) | Sơ đồ ERD và lý do thiết kế từng bảng |
| [docs/03-so-do-lop.md](docs/03-so-do-lop.md) | Sơ đồ lớp, phân tầng, luồng ký và luồng xác minh |
| [docs/04-ke-hoach-kiem-thu.md](docs/04-ke-hoach-kiem-thu.md) | Ca kiểm thử dương và âm, bảng truy vết |
| [docs/05-mo-hinh-de-doa.md](docs/05-mo-hinh-de-doa.md) | Tài sản, kẻ tấn công, điều công cụ không bảo vệ được |
| [docs/06-runbook-khoa-bi-lo.md](docs/06-runbook-khoa-bi-lo.md) | Quy trình xử lý khi khóa ký bị lộ |
| [data/schema.sql](data/schema.sql) | Lược đồ cơ sở dữ liệu, chạy được ngay |

## Môi trường

| Thành phần | Phiên bản |
| --- | --- |
| Python | 3.11 trở lên |
| cryptography | 43.0.1 |
| pytest | 8.3.3 |
| Hệ điều hành đã thử | Ubuntu 24.04, Windows 11 |

Ghi lại phiên bản thực tế của máy chạy bằng `python -V` và `pip freeze`
rồi dán vào báo cáo. Đề bài yêu cầu ghi phiên bản công cụ.

## Cài đặt

```bash
git clone https://github.com/duylong06/AnToanThongTin_ChuKySo_Project.git
cd AnToanThongTin_ChuKySo_Project
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -c "import sqlite3,pathlib;sqlite3.connect('data/sigtool.db').executescript(pathlib.Path('data/schema.sql').read_text(encoding='utf-8'))"
```

## Chạy

```bash
export PYTHONPATH=src                  # Windows: set PYTHONPATH=src

python -m dt19 keygen   --alg ed25519 --owner C
python -m dt19 manifest --dir artifacts/
python -m dt19 sign     --alg ed25519 artifacts/app.bin
python -m dt19 verify   artifacts/app.bin signatures/app.bin.sig
python -m dt19 rotate   --old <key_id> --new-alg ed25519 --overlap-days 14
python -m dt19 revoke   --key <key_id> --reason "khoa bi lo"
python -m dt19 bench    --iterations 100 --size 1048576
```

## Kiểm thử

```bash
pytest -q --cov=src/dt19 --cov-report=term-missing
```

Ca kiểm thử âm quan trọng hơn ca dương: chúng chứng minh rằng mọi sửa đổi
trên nội dung hay metadata đều bị phát hiện. Xem `tests/test_tamper.py`.

## Tái lập kết quả

1. Dùng đúng phiên bản thư viện trong `requirements.txt`.
2. Chạy benchmark với cùng tham số: `--iterations 100 --size 1048576`.
3. Ghi tên máy và cấu hình vào cột `machine` của `results/bench.csv`.
4. So trung vị, không so giá trị đơn lẻ. Máy khác cho con số khác, nhưng
   **thứ tự giữa ba thuật toán phải giữ nguyên** — đó mới là kết luận.

## Hoàn nguyên

```bash
rm -f data/sigtool.db results/*.csv results/*.jsonl
rm -rf keys/*/ signatures/
# rồi chạy lại bước khởi tạo cơ sở dữ liệu ở phần Cài đặt
```

## Phân công

| Thành viên | Mã nguồn | Thực nghiệm | Lý thuyết trình bày |
| --- | --- | --- | --- |
| A | `signers.py` (RSA-PSS), `services.py` (ký), `cli.py` | Benchmark ba thuật toán | Mô hình chữ ký số, RSA-PSS |
| B | `models.py`, `repository.py`, `services.py` (xác minh) | Ca kiểm thử âm, nhật ký xác minh | Toàn vẹn, ECDSA và rủi ro nonce |
| C | `trust.py`, dấu thời gian, thu hồi | Luân chuyển khóa, kịch bản khóa bị lộ | EdDSA, vòng đời khóa, giới hạn chống chối bỏ |

Cả ba cùng tham gia thiết kế, phân tích và bảo vệ. Đề bài nói rõ không được
chia theo kiểu một người chỉ viết báo cáo.

## Công khai sử dụng AI

| Công cụ | Nội dung hỗ trợ | Phần nhóm tự chịu trách nhiệm |
| --- | --- | --- |
| *(điền)* | *(điền)* | *(điền)* |
