@echo off
setlocal enabledelayedexpansion

:: Define paths for compilers (adjust if necessary)
set "iscc_path=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
set "builder_path=C:\Program Files\InstallBuilder Enterprise 25.10.1\bin\builder-cli.exe"

:: Get repo directory
set "repo_dir=%CD%"

:: Get Downloads directory
set "downloads=%USERPROFILE%\Downloads"

:: Get Documents directory
set "docs=%USERPROFILE%\Documents\InstallBuilder\output"

:: Ask for release version
set /p version="Enter the release version (e.g., 1.0.0): "
set "tag=v%version%"
set "title=BlackHole %version%"

:: Get current date in YYYY-MM-DD
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YYYY=%dt:~0,4%"
set "MM=%dt:~4,2%"
set "DD=%dt:~6,2%"
set "today=%YYYY%-%MM%-%DD%"

:: Move Extras contents directly to Downloads (optimized, no need to copy to target first)
echo Moving Extras contents to Downloads...
set "extras=%repo_dir%\Extras"
if exist "%extras%" (
    echo Moving contents from Extras:
    for %%i in ("%extras%\*") do (
        echo Copying %%i to %downloads%
        copy "%%i" "%downloads%" > nul
    )
)
call :progress 10
echo.

:: Step 1: Create and populate Windows target with only necessary files/folders
echo Setting up Windows target...
set "target_win=%downloads%\BlackHole"
if exist "%target_win%" rmdir /s /q "%target_win%"
mkdir "%target_win%"
echo Copying necessary directories and files:
robocopy "%repo_dir%\Fonts" "%target_win%\Fonts" /E
robocopy "%repo_dir%\Icons" "%target_win%\Icons" /E
echo Copying BlackHole.exe
copy "%repo_dir%\BlackHole.exe" "%target_win%" > nul
echo Copying LICENSE.txt
copy "%repo_dir%\LICENSE.txt" "%target_win%" > nul
call :progress 20
echo.

:: Step 2: Create and populate Linux target with only necessary files/folders
echo Setting up Linux target...
set "target_linux_dir=%downloads%\Linux"
if exist "%target_linux_dir%" rmdir /s /q "%target_linux_dir%"
mkdir "%target_linux_dir%"
set "target_linux=%target_linux_dir%\BlackHole"
mkdir "%target_linux%"
echo Copying necessary directories and files:
robocopy "%repo_dir%\Fonts" "%target_linux%\Fonts" /E
robocopy "%repo_dir%\Icons" "%target_linux%\Icons" /E
echo Copying BlackHole
copy "%repo_dir%\BlackHole" "%target_linux%" > nul
echo Copying LICENSE.txt
copy "%repo_dir%\LICENSE.txt" "%target_linux%" > nul
echo Copying README.txt
copy "%repo_dir%\README.txt" "%target_linux%" > nul
call :progress 30
echo.

:: Step 3: Zip the targets
echo Zipping targets...
powershell -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%target_win%\*' -DestinationPath '%downloads%\Windows-BlackHole.zip' -Force"
powershell -ExecutionPolicy Bypass -Command "Compress-Archive -Path '%target_linux%\*' -DestinationPath '%downloads%\Linux-BlackHole.zip' -Force"
call :progress 40
echo.

:: Step 4: Build Windows installer
echo Building Windows installer...
echo Compiling using Inno Setup with file: %downloads%\BlackHole.iss
set "iss_path=%downloads%\BlackHole.iss"
"%iscc_path%" "%iss_path%"
set "windows_installer=%downloads%\Black_hole_setup.exe"
call :progress 50
echo.

:: Step 5: Build Linux installer and move to Downloads
echo Building Linux installer...
echo Compiling using InstallBuilder with file: %repo_dir%\Extras\BlackHole.xml for linux-x64
set "xml_path=%repo_dir%\Extras\BlackHole.xml"
"%builder_path%" build "%xml_path%" linux-x64
set "linux_installer=%docs%\BlackHole-%version%-linux-x64-installer.run"
set "linux_installer_final=%downloads%\BlackHole-%version%-linux-x64-installer.run"
move "%linux_installer%" "%linux_installer_final%" > nul
call :progress 60
echo.

:: Cleanup: Remove temporary folders and files, keeping only specified items
echo Cleaning up...
rmdir /s /q "%target_win%"
rmdir /s /q "%target_linux_dir%"
del /q "%downloads%\BlackHole.iss"
del /q "%downloads%\BlackHole.xml"
del /q "%downloads%\Black Hole Installer.ico"
del /q "%downloads%\Black Hole Installer.png"
:: Add more del if there are other files from Extras
call :progress 100
echo.

echo Setup complete. Check Downloads folder for: Black hole.png, Windows-BlackHole.zip, Linux-BlackHole.zip, Black_hole_setup.exe, BlackHole-%version%-linux-x64-installer.run
pause

:: Exit main script before subroutines
goto :eof

:: Function to show progress bar
:progress
if "%1"=="" (set /a percent=0) else (set /a percent=%1)
set "bar="
set /a "width=50"  :: Adjustable width for the bar (shorter for cleaner output)
for /l %%i in (1,1,%percent%) do set "bar=!bar!#"
set /a "next=percent + 1"
for /l %%i in (%next%,1,%width%) do set "bar=!bar! "
echo | set /p "=[!bar!] !percent!%%"
goto :eof