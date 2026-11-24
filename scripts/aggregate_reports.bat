@echo off
chcp 65001 >nul
setlocal

set "ROOT_DIR=%~dp0.."
set "PY_CMD=python"
if exist "%ROOT_DIR%\.venv\Scripts\python.exe" set "PY_CMD=%ROOT_DIR%\.venv\Scripts\python.exe"

if not exist "%ROOT_DIR%\reports\repos" (
    echo [LOI] Chua co thu muc reports\repos\. Hay chay scan_folder.bat cho tung du an truoc.
    if "%NO_PAUSE%"=="" pause
    exit /b 1
)

echo ============================================================================
echo  TONG HOP THONG KE NHIEU DO AN (reports\repos\*.json)
echo ============================================================================
"%PY_CMD%" "%ROOT_DIR%\scripts\pipeline.py" --mode aggregate --aggregate-dir "%ROOT_DIR%\reports\repos" --out-json "%ROOT_DIR%\reports\aggregate_report.json" --out-md "%ROOT_DIR%\reports\AGGREGATE_SUMMARY.md"

echo ============================================================================
echo  HOAN TAT! Mo file reports\AGGREGATE_SUMMARY.md de xem bang thong ke tong hop.
echo ============================================================================
if "%NO_PAUSE%"=="" pause
