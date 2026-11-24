# Hướng dẫn Thực nghiệm Đề tài: Quét Cloud Sandbox, Ẩn danh & Đánh giá Thủ công

Tài liệu gộp toàn bộ quy trình thực nghiệm để hoàn thiện số liệu báo cáo đề tài.

---

## 1. Quét đồ án sinh viên (Đã ẩn danh, có đồng ý)
1. Tạo danh sách xác nhận đồng ý (`consented = yes/no`):
   ```powershell
   python scripts\prepare_student_repos.py --init-manifest dataset\consent_manifest.csv
   ```
2. Đặt các đồ án thô vào `dataset\raw_student_repos\` và chạy quét hàng loạt (script tự loại bỏ `.git`, `.env*`, `*.pem`, `*.key` và bỏ qua đồ án chưa đồng ý):
   ```powershell
   python scripts\prepare_student_repos.py --raw-dir dataset\raw_student_repos --manifest dataset\consent_manifest.csv
   ```
   Báo cáo tổng hợp đa đồ án xuất ra tại `reports\AGGREGATE_SUMMARY.md` (hoặc chạy lại bằng `.\scripts\aggregate_reports.bat`).

---

## 2. Sinh gợi ý sửa bằng LLM (Gemini API) & Kiểm chứng quét lại
```powershell
$env:GEMINI_API_KEY="API_KEY_CUA_BAN"
python scripts\llm_remediate_and_verify.py --source "D:\duong_dan\ThuMucDoAn" --repo-id DO_AN_01
```
Báo cáo tỷ lệ vượt quét lại thực tế của LLM xuất ra tại `reports\LLM_VERIFICATION_REPORT.md`.

---

## 3. Quét tài khoản đám mây thử nghiệm (Prowler / ScoutSuite)
1. Cấu hình profile AWS Sandbox chỉ có quyền đọc (`ReadOnlyAccess` / `SecurityAudit`):
   ```powershell
   aws configure --profile student-lab
   ```
2. Chạy **Prowler** (tự ẩn danh Account ID và xuất báo cáo `reports\CLOUD_AUDIT_REPORT.md`):
   ```powershell
   pip install prowler
   .\scripts\run_prowler_cloud_audit.bat student-lab CLOUD_SANDBOX_01
   ```
3. *(Tùy chọn đối chiếu trực quan bằng ScoutSuite)*:
   ```powershell
   pip install scoutsuite
   scout aws --profile student-lab --services ec2 s3 rds iam --report-dir reports\scoutsuite
   ```

---

## 4. Biểu mẫu đánh giá thủ công một mẫu gợi ý LLM
Chấm điểm mẫu gợi ý do Gemini API sinh ra theo thang **0–2** mỗi tiêu chí:
- **Đúng bảo mật (0–2):** `2` = triệt để đúng best practice; `1` = giảm thiểu một phần; `0` = sai hướng.
- **Giữ chức năng (0–2):** `2` = hợp lệ cú pháp (`terraform validate` / `docker compose config` đạt); `1` = cần chỉnh nhẹ; `0` = phá vỡ cấu hình.

| STT | Mã Finding (`finding_id`) | Quy tắc (`rule_id`) | Nhóm lỗi | Đúng bảo mật (0-2) | Giữ chức năng (0-2) | Vượt quét lại (Pass/Fail) | Ghi chú |
|---|---|---|---|---:|---:|---|---|
| 1 | `...` | `CKV_AWS_24` | Overly Permissive Access | - | - | - | - |
| 2 | `...` | `CKV_AWS_20` | Public Storage | - | - | - | - |
| 3 | `...` | `CKV_SECRET_2` | Hardcoded Secrets | - | - | - | - |
