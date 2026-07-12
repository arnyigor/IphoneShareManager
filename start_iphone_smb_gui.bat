@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0iphone_smb_gui.py"
    goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
    python "%~dp0iphone_smb_gui.py"
    goto :eof
)

echo Python 3 не найден.
echo Установите Python 3 для Windows и включите пункт "Add Python to PATH".
pause
