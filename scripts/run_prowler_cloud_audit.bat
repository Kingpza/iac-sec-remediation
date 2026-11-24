@echo off
chcp 65001 >nul
setlocal

set "AWS_PROFILE_ARG="
if not "%~1"=="" set "AWS_PROFILE_ARG=--profile %~1"
set "REPO_ID=%~2"
if "%REPO_ID%"=="" set "REPO_ID=CLOUD_SANDBOX_01"

set "PY_CMD=python"
if exist "%~dp0.venv\Scripts\python.exe" set "PY_CMD=%~dp0.venv\Scripts\python.exe"

where prowler >nul 2>nul
if errorlevel 1 (
    echo [LOI] Chua cai dat Prowler CLI. Cai bang: pip install prowler
    echo Xem huong dan chi tiet tai: docs\THESIS_GUIDE.md
    if "%NO_PAUSE%"=="" pause
    exit /b 1
)

if not exist "%~dp0reports\prowler" mkdir "%~dp0reports\prowler"
if not exist "%~dp0reports\repos" mkdir "%~dp0reports\repos"
del /q "%~dp0reports\prowler\*.json" 2>nul

echo ============================================================================
echo  QUET TAI KHOAN DAM MAY THU NGHIEM BANG PROWLER (REPO_ID: %REPO_ID%)
echo ============================================================================
prowler aws %AWS_PROFILE_ARG% --services ec2 s3 rds iam --output-formats json-ocsf --output-directory "%~dp0reports\prowler" --output-filename prowler_before

if not exist "%~dp0reports\prowler\prowler_before.ocsf.json" (
    echo [CANH BAO] Khong tim thay file prowler_before.ocsf.json. Kiem tra lai quyen AWS CLI.
    if "%NO_PAUSE%"=="" pause
    exit /b 1
)

"%PY_CMD%" "%~dp0scripts\pipeline.py" --mode scan --repo-id "%REPO_ID%" --checkov-before "" --gitleaks-before "" --prowler-before "%~dp0reports\prowler\prowler_before.ocsf.json" --out-json "%~dp0reports\repos\%REPO_ID%_cloud.json" --out-md "%~dp0reports\CLOUD_AUDIT_REPORT.md"

echo ============================================================================
echo  HOAN TAT! Bao cao cloud runtime: reports\CLOUD_AUDIT_REPORT.md
echo ============================================================================
if "%NO_PAUSE%"=="" pause
