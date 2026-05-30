@echo off
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

echo.
echo  [96m Stopping LateralX...[0m

set /a found=0
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr "127.0.0.1:8000 " ^| findstr LISTENING') do (
    taskkill /PID %%p /F >nul 2>&1
    set /a found=1
)

if %found%==1 (
    echo  [96m✓[0m [37mLateralX stopped.[0m
) else (
    echo  [90mLateralX was not running.[0m
)
echo.
timeout /t 2 /nobreak >nul
