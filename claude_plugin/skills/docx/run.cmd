@echo off
rem docx skill launcher — Python 位置优先级:
rem   1) 环境变量 CLOUD_GUARD_PYTHON 指定的 python.exe(部署时由安装脚本写入)
rem   2) 插件目录 bin\_internal\python.exe(未来若真用 PyInstaller onedir)
rem   3) 系统 py -3(开发机)
setlocal
set "SELF_DIR=%~dp0"
set "PLUGIN_ROOT=%SELF_DIR%..\.."

if defined CLOUD_GUARD_PYTHON (
  if exist "%CLOUD_GUARD_PYTHON%" (
    "%CLOUD_GUARD_PYTHON%" "%SELF_DIR%docx_to_md.py" %*
    exit /b %errorlevel%
  )
)
if exist "%PLUGIN_ROOT%\bin\_internal\python.exe" (
  "%PLUGIN_ROOT%\bin\_internal\python.exe" "%SELF_DIR%docx_to_md.py" %*
  exit /b %errorlevel%
)
py -3 "%SELF_DIR%docx_to_md.py" %*
exit /b %errorlevel%
