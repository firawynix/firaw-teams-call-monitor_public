@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  py -3 -m venv .venv
  if errorlevel 1 (
    echo Nao foi possivel criar o ambiente Python.
    pause
    exit /b 1
  )
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Nao foi possivel instalar a dependencia.
    pause
    exit /b 1
  )
)
start "" ".venv\Scripts\pythonw.exe" "%~dp0monitor.py"
