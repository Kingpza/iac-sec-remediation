@echo off
chcp 65001 >nul
setlocal

if "%~1"=="" (
    echo [LOI] Vui long keo tha THU MUC do an vao file scan_folder.bat nay,
    echo hoac chay lenh: .\scan_folder.bat "D:\duong_dan\ThuMucDoAn" [REPO_ID]
    if "%NO_PAUSE%"=="" pause
    exit /b 1
)

set "TARGET_DIR=%~f1"
if "%TARGET_DIR:~-1%"=="\" if not "%TARGET_DIR:~-2%"==":\" set "TARGET_DIR=%TARGET_DIR:~0,-1%"
if not exist "%TARGET_DIR%" (
    echo [LOI] Khong tim thay thu muc: "%TARGET_DIR%"
    if "%NO_PAUSE%"=="" pause
    exit /b 1
)

set "REPO_ID=%~2"
if "%REPO_ID%"=="" for %%I in ("%TARGET_DIR%") do set "REPO_ID=%%~nxI"
if "%REPO_ID%"=="" set "REPO_ID=DRIVE_%TARGET_DIR:~0,1%"
set "REPO_ID=%REPO_ID: =_%"

set "PY_CMD=python"
if exist "%~dp0.venv\Scripts\python.exe" set "PY_CMD=%~dp0.venv\Scripts\python.exe"

set "GITLEAKS_CMD="
where gitleaks >nul 2>nul && set "GITLEAKS_CMD=gitleaks"
if "%GITLEAKS_CMD%"=="" if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\gitleaks.exe" set "GITLEAKS_CMD=%LOCALAPPDATA%\Microsoft\WinGet\Links\gitleaks.exe"
if "%GITLEAKS_CMD%"=="" for /f "delims=" %%G in ('dir /b /s "%LOCALAPPDATA%\Microsoft\WinGet\Packages\gitleaks.exe" 2^>nul') do set "GITLEAKS_CMD=%%G"

if not exist "%~dp0reports\raw" mkdir "%~dp0reports\raw"
if not exist "%~dp0reports\repos" mkdir "%~dp0reports\repos"

del /q "%~dp0reports\raw\checkov_before.json" "%~dp0reports\raw\checkov_after.json" "%~dp0reports\raw\gitleaks_before.json" "%~dp0reports\raw\gitleaks_after.json" 2>nul

echo ============================================================================
echo  QUET TOAN BO THU MUC DO AN: %TARGET_DIR% (REPO_ID: %REPO_ID%)
echo ============================================================================

echo [1/3] Quet Checkov (IaC + bi mat tren tat ca tep)...
pushd "%TARGET_DIR%"
"%PY_CMD%" -m checkov.main -d . --skip-download --enable-secret-scan-all-files --quiet --output json --soft-fail > "%~dp0reports\raw\checkov_before.json"
popd

echo [2/3] Quet Gitleaks tim bi mat ghi cung...
if not "%GITLEAKS_CMD%"=="" (
    "%GITLEAKS_CMD%" detect --source="%TARGET_DIR%" --no-git --report-format=json --report-path="%~dp0reports\raw\gitleaks_before.json" --exit-code=0
) else (
    echo     [CANH BAO] Chua tim thay 'gitleaks'; chi dung ket qua Checkov.
)

echo [3/3] Chuan hoa, an danh bi mat, thong ke theo loai va sinh goi y...
"%PY_CMD%" "%~dp0scripts\pipeline.py" --mode scan --repo-id "%REPO_ID%" --source-dir "%TARGET_DIR%" --checkov-before "%~dp0reports\raw\checkov_before.json" --gitleaks-before "%~dp0reports\raw\gitleaks_before.json" --out-json "%~dp0reports\repos\%REPO_ID%.json" --out-md "%~dp0reports\SUMMARY_REPORT.md"
copy /y "%~dp0reports\repos\%REPO_ID%.json" "%~dp0reports\normalized_remediation_report.json" >nul

echo ============================================================================
echo  HOAN TAT!
echo  - Bao cao chi tiet: reports\SUMMARY_REPORT.md
echo  - Du lieu tong hop: reports\repos\%REPO_ID%.json
echo ============================================================================
if "%NO_PAUSE%"=="" pause
