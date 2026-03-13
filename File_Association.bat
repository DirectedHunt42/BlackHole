@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "APP_EXE=%SCRIPT_DIR%BlackHole.exe"
set "HAWKING_ICON_PATH=%SCRIPT_DIR%Icons\Hawking_Icon.ico"
set "SINGULARITY_ICON_PATH=%SCRIPT_DIR%Icons\Singularity_Icon.ico"
set "HAWKING_PROG_ID=BlackHole.Hawking"
set "SINGULARITY_PROG_ID=BlackHole.Singularity"

set "ARG=%~1"
if /I "%ARG%"=="--install" goto :install
if /I "%ARG%"=="-install" goto :install
if /I "%ARG%"=="/install" goto :install
if /I "%ARG%"=="install" goto :install
if /I "%ARG%"=="--uninstall" goto :uninstall
if /I "%ARG%"=="-uninstall" goto :uninstall
if /I "%ARG%"=="/uninstall" goto :uninstall
if /I "%ARG%"=="uninstall" goto :uninstall
if "%ARG%"=="" goto :install

echo Usage: %~nx0 [install^|uninstall]
exit /b 1

:install
echo Registering file associations for current user...
reg add "HKCU\Software\Classes\.hawking" /ve /d "%HAWKING_PROG_ID%" /f >nul
reg add "HKCU\Software\Classes\%HAWKING_PROG_ID%" /ve /d "Hawking Icon Pack" /f >nul
reg add "HKCU\Software\Classes\%HAWKING_PROG_ID%\DefaultIcon" /ve /d "%HAWKING_ICON_PATH%" /f >nul
reg add "HKCU\Software\Classes\%HAWKING_PROG_ID%\shell\open\command" /ve /d "\"%APP_EXE%\" \"%%1\"" /f >nul

reg add "HKCU\Software\Classes\.singularity" /ve /d "%SINGULARITY_PROG_ID%" /f >nul
reg add "HKCU\Software\Classes\.signularity" /ve /d "%SINGULARITY_PROG_ID%" /f >nul
reg add "HKCU\Software\Classes\.sungularity" /ve /d "%SINGULARITY_PROG_ID%" /f >nul
reg add "HKCU\Software\Classes\%SINGULARITY_PROG_ID%" /ve /d "Singularity Vault" /f >nul
reg add "HKCU\Software\Classes\%SINGULARITY_PROG_ID%\DefaultIcon" /ve /d "%SINGULARITY_ICON_PATH%" /f >nul
reg add "HKCU\Software\Classes\%SINGULARITY_PROG_ID%\shell\open\command" /ve /d "\"%APP_EXE%\" \"%%1\"" /f >nul
echo Done.
exit /b 0

:uninstall
echo Removing file associations for current user...
reg delete "HKCU\Software\Classes\.hawking" /f >nul
reg delete "HKCU\Software\Classes\%HAWKING_PROG_ID%" /f >nul
reg delete "HKCU\Software\Classes\.singularity" /f >nul
reg delete "HKCU\Software\Classes\.signularity" /f >nul
reg delete "HKCU\Software\Classes\.sungularity" /f >nul
reg delete "HKCU\Software\Classes\%SINGULARITY_PROG_ID%" /f >nul
echo Done.
exit /b 0
