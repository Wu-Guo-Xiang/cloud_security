@echo off
setlocal
set "SELF_DIR=%~dp0"
set "PY_SCRIPT=%SELF_DIR%..\src\input\input_scanner.py"

if defined CLOUD_GUARD_PYTHON (
  if exist "%CLOUD_GUARD_PYTHON%" (
    "%CLOUD_GUARD_PYTHON%" "%PY_SCRIPT%" %*
    exit /b %errorlevel%
  )
)
py -3 "%PY_SCRIPT%" %*
exit /b %errorlevel%
