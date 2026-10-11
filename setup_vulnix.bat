@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher not found. Install Python 3.10+ from python.org, enable the launcher, then run this file again.
  pause
  exit /b 1
)
py -3 -m venv .venv
if errorlevel 1 (
  echo Could not create the virtual environment. Confirm that Python 3.10+ is installed.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 goto fail
python -m pip install -r requirements.txt
if errorlevel 1 goto fail
echo.
echo Setup complete. Double-click run_vulnix.bat to launch Vulnix AI.
pause
exit /b 0
:fail
echo.
echo Dependency installation failed. Check your internet connection and Python installation.
pause
exit /b 1
