@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 goto NO_PYTHON

echo Starting Sepahr Security Observatory setup...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 goto PIP_WARN

:LAUNCH_APP
start "" http://127.0.0.1:8094
python main.py --host 127.0.0.1 --port 8094
goto END_SCRIPT

:PIP_WARN
echo Warning: pip install encountered an issue, attempting launch with existing packages...
goto LAUNCH_APP

:NO_PYTHON
echo Error: Python 3.10 or newer was not found in PATH.
pause
exit /b 1

:END_SCRIPT
endlocal
