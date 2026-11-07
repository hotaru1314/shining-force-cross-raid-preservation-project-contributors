@echo off
setlocal
cd /d "%~dp0"
echo === SFCR client launcher (CMD) ===
if not exist "launch_client.py" (
    echo [!] launch_client.py is missing next to this .bat.
    echo     Extract the WHOLE client folder from client_pkg_20261024.zip
    echo     ^(do not copy only a few files^).
    pause
    exit /b 1
)
if exist "python\python.exe" (
    "python\python.exe" launch_client.py %*
) else (
    python launch_client.py %*
)
echo.
pause
