@echo off
setlocal
set "SELF_DIR=%~dp0"
set "PY_SCRIPT=%SELF_DIR%..\src\updater\updater.py"

REM 1. 优先检查默认部署目录 D:\ClaudeSecurity\python\python.exe
if exist "D:\ClaudeSecurity\python\python.exe" (
  "D:\ClaudeSecurity\python\python.exe" "%PY_SCRIPT%" %*
  pause
  exit /b %errorlevel%
)

REM 2. 检查环境变量 CLOUD_GUARD_PYTHON
if defined CLOUD_GUARD_PYTHON (
  if exist "%CLOUD_GUARD_PYTHON%" (
    "%CLOUD_GUARD_PYTHON%" "%PY_SCRIPT%" %*
    pause
    exit /b %errorlevel%
  )
)

REM 3. 检查相对目录推导
set "BUNDLED_PY=%SELF_DIR%..\..\..\..\ClaudeSecurity\python\python.exe"
if exist "%BUNDLED_PY%" (
  "%BUNDLED_PY%" "%PY_SCRIPT%" %*
  pause
  exit /b %errorlevel%
)

REM 4. 回退系统 Python
py -3 "%PY_SCRIPT%" %*
pause
exit /b %errorlevel%
