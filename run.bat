@echo off
REM One-click launcher: first run installs everything, later runs just start the app.
cd /d "%~dp0"
title PacketScope - Network Traffic Analyzer

set PY=
where py >nul 2>nul && set PY=py -3
if "%PY%"=="" where python >nul 2>nul && set PY=python
if "%PY%"=="" goto nopython

if exist ".venv\Scripts\python.exe" goto run

echo First-time setup - this takes a minute or two...
%PY% -m venv .venv
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed

:run
if not exist ".env" copy ".env.example" ".env" >nul
echo Starting the dashboard - your browser will open. Close this window to stop it.
".venv\Scripts\python.exe" -m streamlit run app.py
goto end

:nopython
echo Python 3.11 or newer was not found.
echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
goto end

:failed
echo Setup failed - see the messages above.

:end
pause
