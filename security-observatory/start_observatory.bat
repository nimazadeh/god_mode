@echo off
setlocal
cd /d "%~dp0"
start "" http://127.0.0.1:8094
python main.py --host 127.0.0.1 --port 8094
endlocal
