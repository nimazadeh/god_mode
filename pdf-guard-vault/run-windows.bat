@echo off
chcp 65001 >nul
title PDF-Guard and Course Vault v1.0.0
echo ============================================================
echo   PDF-Guard and Course Vault v1.0.0 - Starting Server
echo ============================================================
if exist .venv\Scripts\python.exe goto VENV_READY
echo Creating Python virtual environment...
python -m venv .venv
:VENV_READY
call .venv\Scripts\activate.bat
pip install --quiet --disable-pip-version-check -r requirements.txt
start http://127.0.0.1:8092
python main.py --host 127.0.0.1 --port 8092
pause
