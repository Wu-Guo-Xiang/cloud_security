@echo off
rem xlsx-redact skill launcher — Python 位置优先级见 docx/run.cmd
setlocal
set "SELF_DIR=%~dp0"
set "PLUGIN_ROOT=%SELF_DIR%..\.."

if defined CLOUD_GUARD_PYTHON (
  if exist "%CLOUD_GUARD_PYTHON%" (
    "%CLOUD_GUARD_PYTHON%" "%SELF_DIR%xlsx_to_md.py" %*
    exit /b %errorlevel%
  )
)
if exist "%PLUGIN_ROOT%\bin\_internal\python.exe" (
  "%PLUGIN_ROOT%\bin\_internal\python.exe" "%SELF_DIR%xlsx_to_md.py" %*
  exit /b %errorlevel%
)
py -3 "%SELF_DIR%xlsx_to_md.py" %*
exit /b %errorlevel%
