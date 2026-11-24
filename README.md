# Quét lỗi cấu hình bảo mật trong mã hạ tầng của đồ án sinh viên và sinh gợi ý khắc phục

Hệ thống hỗ trợ quét tĩnh cấu hình hạ tầng (**Checkov**: Terraform, Dockerfile, Docker Compose, Kubernetes...) và rà soát bí mật ghi cứng (**Gitleaks**), kết hợp quét mở rộng mã nguồn/cấu hình ứng dụng, hỗ trợ đọc báo cáo đám mây (**Prowler**), tự động ẩn danh dữ liệu nhạy cảm (`<REDACTED_...>`), phân loại theo 4 nhóm lỗi chuẩn, gọi **Gemini API** sinh gợi ý khắc phục và kiểm chứng hiệu quả bằng cách quét lại.

## Cấu trúc dự án
- `.github/actions/iac-sec-scan/action.yml`: Composite GitHub Action gắn được vào kho mã đồ án bất kỳ.
- `.github/workflows/iac-security-scan.yml`: Workflow CI mẫu chạy tự động trên GitHub.
- `docs/THESIS_GUIDE.md`: Hướng dẫn thực nghiệm chi tiết (xác nhận đồng ý & ẩn danh tập đồ án, chạy LLM kiểm chứng, quét Prowler/ScoutSuite và biểu mẫu đánh giá thủ công).
- `scripts/`:
  - `pipeline.py`: Lõi chuẩn hóa phát hiện, ẩn danh bí mật, sinh gợi ý Gemini, đối chiếu trước/sau (`verify`) và tổng hợp đa đồ án (`aggregate`).
  - `llm_remediate_and_verify.py`: Tạo bản sao cô lập, gọi Gemini API vá lỗi theo tệp và quét lại để đo tỷ lệ vượt quét lại.
  - `prepare_student_repos.py`: Kiểm tra xác nhận đồng ý (`consent_manifest.csv`), loại bỏ `.git`/bí mật cục bộ và quét hàng loạt đồ án sinh viên.
  - `aggregate_reports.bat`: Tổng hợp báo cáo nhiều đồ án thành bảng thống kê chung.
  - `run_prowler_cloud_audit.bat`: Quét tài khoản đám mây thử nghiệm bằng Prowler (tách riêng khỏi số liệu quét tĩnh).
- `scan_folder.bat`: Script chạy nhanh để quét một thư mục đồ án bất kỳ trên Windows.
- `.gitleaks.toml`: Cấu hình loại trừ thư mục báo cáo/hệ thống khi chạy Gitleaks.
- `reports/`: Thư mục xuất báo cáo (`SUMMARY_REPORT.md`, `normalized_remediation_report.json`, `AGGREGATE_SUMMARY.md`...).

---

## Cách 1: Chạy trực tiếp trên máy (Windows / Local)

### Bước 1. Cài đặt môi trường (chỉ làm 1 lần)
1. Cài **Python 3.10+** và cài Checkov:
   ```powershell
   pip install checkov
   ```
2. *(Tùy chọn)* Cài **Gitleaks** để rà soát bí mật ghi cứng:
   ```powershell
   winget install Gitleaks.Gitleaks
   ```
3. *(Tùy chọn)* Nếu muốn sinh gợi ý khắc phục từ Gemini API, đặt biến môi trường trước khi chạy (bỏ qua nếu chỉ cần quét và thống kê):
   ```powershell
   $env:GEMINI_API_KEY="API_KEY_CUA_BAN"
   ```

### Bước 2. Quét một thư mục đồ án
- Kéo thả thư mục đồ án vào tệp `scan_folder.bat`, hoặc chạy bằng PowerShell:
  ```powershell
  .\scan_folder.bat "D:\duong_dan\ThuMucDoAn"
  ```
- Báo cáo chi tiết xuất ra tại `reports\SUMMARY_REPORT.md` và dữ liệu JSON tại `reports\repos\<REPO_ID>.json`.

### Bước 3. Sinh gợi ý sửa bằng LLM & kiểm chứng quét lại (tùy chọn)
```powershell
python scripts\llm_remediate_and_verify.py --source "D:\duong_dan\ThuMucDoAn" --repo-id DO_AN_01
```
- Kết quả đối chiếu trước/sau và tỷ lệ vượt quét lại xuất tại `reports\LLM_VERIFICATION_REPORT.md`.

### Bước 4. Quét hàng loạt & tổng hợp nhiều đồ án
- Nếu tổng hợp các đồ án đã chạy bằng `scan_folder.bat`:
  ```powershell
  .\scripts\aggregate_reports.bat
  ```
- Nếu quét hàng loạt theo danh sách đồng ý & ẩn danh (`consent_manifest.csv`), xem chi tiết tại `docs/THESIS_GUIDE.md`. Kết quả tổng hợp xuất tại `reports\AGGREGATE_SUMMARY.md`.

---

## Cách 2: Gắn GitHub Action vào kho mã đồ án khác (Chạy trên GitHub)

Cách này chạy hoàn toàn trên máy chủ GitHub khi có `push` hoặc `pull_request` — máy cá nhân của người dùng **không cần cài đặt** Python, Checkov hay Gitleaks.

> **Lưu ý:** Kho `Kingpza/iac-sec-remediation` cần được đặt ở chế độ **Public** để các kho đồ án khác có thể tham chiếu trực tiếp Action.

1. Trong kho đồ án cần quét, tạo tệp `.github/workflows/iac-scan.yml` với nội dung:
   ```yaml
   name: IaC Security Scan
   on: [push, pull_request]

   jobs:
     iac-scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
           with:
             fetch-depth: 0
         - uses: Kingpza/iac-sec-remediation/.github/actions/iac-sec-scan@main
           with:
             target_dir: "."
             repo_id: ${{ github.repository }}
             # Tùy chọn: bỏ dòng dưới nếu chỉ quét tĩnh không dùng LLM
             gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
         - uses: actions/upload-artifact@v4
           with:
             name: iac-security-report
             path: reports/
   ```
2. *(Tùy chọn)* Nếu muốn bật gợi ý sửa bằng Gemini, vào **Settings → Secrets and variables → Actions** của kho đồ án và thêm secret tên `GEMINI_API_KEY`.
3. Sau khi đẩy mã lên GitHub, vào tab **Actions** để xem bảng thống kê trực tiếp ở mục **Summary** hoặc tải về gói `iac-security-report` ở mục **Artifacts**.
