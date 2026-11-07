@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PY=%~dp0python\python.exe
if not exist "%PY%" set PY=python
if "%~1"=="" goto run
"%PY%" run_server.py %*
goto end
:run
echo === Shining Force Cross Raid -- fake cabinet ===
"%PY%" run_server.py
:end
pause