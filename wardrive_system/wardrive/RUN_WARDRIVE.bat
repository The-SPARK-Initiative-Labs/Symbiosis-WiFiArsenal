@echo off
REM RUN_WARDRIVE.bat - Windows version

cd /d "%~dp0"

set "VENV_DIR=%~dp0..\venv_windows"

echo ============================================
echo     WARDRIVE MAPPER - Windows Edition
echo ============================================
echo.

if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found
    pause
    exit /b 1
)

call "%VENV_DIR%\Scripts\activate.bat"

set WARDRIVE_COUNT=0
for %%F in (wardrive*.txt) do set /a WARDRIVE_COUNT+=1

if %WARDRIVE_COUNT%==0 (
    echo No wardrive*.txt files found
    echo.
    pause
    exit /b 1
)

echo Found %WARDRIVE_COUNT% wardrive file(s) to process
echo.

set /p DOWNLOAD_CHOICE="Download offline map tiles? (Y/N, default=N): "
if "%DOWNLOAD_CHOICE%"=="" set DOWNLOAD_CHOICE=N

echo.
echo Processing wardrive data...
echo.

for %%F in (wardrive*.txt) do (
    echo Processing: %%F
    python wardrive_mapper.py "%%F"
)

echo.
echo Map generation complete!
echo.

if /i "%DOWNLOAD_CHOICE%"=="Y" (
    echo Downloading map tiles...
    python download_tiles.py
    echo.
)

set "HTML_FILE=%~dp0..\wardrive_master_map.html"
if exist "%HTML_FILE%" (
    echo Opening map in browser...
    start "" "%HTML_FILE%"
)

echo.
pause

deactivate
