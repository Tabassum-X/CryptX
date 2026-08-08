@echo off
title CryptX
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Python is not installed yet.
  echo   Opening the Python download page for you now...
  echo.
  echo   On that page:  click the big yellow "Download Python" button,
  echo   open the downloaded file, TICK the box "Add python.exe to PATH",
  echo   then click "Install Now".
  echo   When it finishes, just double-click this file again.
  echo.
  start "" https://www.python.org/downloads/
  pause
  exit /b
)

echo.
echo   Preparing CryptX. The first run installs a few components -
echo   this can take a minute or two. Please wait...
echo.
python -m pip install --quiet --disable-pip-version-check flask cryptography argon2-cffi kyber-py dilithium-py

echo.
echo   Launching CryptX. Your browser will open automatically.
echo.
python cryptx_app.py

echo.
echo   ------------------------------------------------------------
echo   CryptX has stopped. If there is red text above, take a
echo   screenshot of this window so it can be fixed.
echo   ------------------------------------------------------------
pause
