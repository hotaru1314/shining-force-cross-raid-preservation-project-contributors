@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    echo [!] run this script as Administrator ^(right-click -^> Run as administrator^)
    pause
    exit /b 1
)
if not exist "card\iccard_seed.bin" (
    echo [!] card\iccard_seed.bin not found
    pause
    exit /b 1
)
if exist C:\iccard.bin (
    copy /y C:\iccard.bin "card\iccard_prev.bin" >nul
    echo backed up existing card -^> card\iccard_prev.bin
)
if exist C:\iccard.txt (
    copy /y C:\iccard.txt "card\iccard_prev.txt" >nul
)
copy /y "card\iccard_seed.bin" C:\iccard.bin >nul
icacls C:\iccard.bin /setintegritylevel Low >nul
icacls C:\iccard.bin /grant "%USERNAME%:(M)" >nul
if exist "card\iccard.txt" (
    copy /y "card\iccard.txt" C:\iccard.txt >nul
    icacls C:\iccard.txt /setintegritylevel Low >nul
    icacls C:\iccard.txt /grant "%USERNAME%:(M)" >nul
    echo seeded C:\iccard.txt
)
echo seeded C:\iccard.bin
dir C:\iccard.bin | findstr /i iccard
pause
