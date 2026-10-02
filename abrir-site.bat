@echo off
setlocal
cd /d "%~dp0"
set "SITE_URL=http://127.0.0.1:4188/"
curl.exe --fail --silent --max-time 2 "%SITE_URL%" | findstr /C:"Monitor de Chamadas para Teams" >nul
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath 'py' -ArgumentList @('-3','-m','http.server','4188','--bind','127.0.0.1','--directory','site') -WorkingDirectory '%~dp0' -WindowStyle Hidden"
  powershell -NoProfile -Command "Start-Sleep -Seconds 2"
)
curl.exe --fail --silent --max-time 2 "%SITE_URL%" | findstr /C:"Monitor de Chamadas para Teams" >nul
if errorlevel 1 (
  echo Nao foi possivel abrir o site do Teams na porta 4188. Verifique se outro programa esta usando essa porta.
  pause
  exit /b 1
)
start "" "%SITE_URL%"
