@echo off
setlocal EnableExtensions
cd /d "%~dp0"

:MENU
cls
echo.
echo  =====================================
echo              ArmorAV 4.2.4
echo  =====================================
echo.
echo  [1] CLI scanner
echo  [2] Browser Console
echo  [Q] Exit
echo.
choice /C 12Q /N /M "Select an option"
if errorlevel 3 goto END
if errorlevel 2 goto WEB
if errorlevel 1 goto CLI

:CLI
call :ENSURE_CLI
if errorlevel 1 goto MENU
set "PATH=%~dp0artifacts\win-x64\cli;%PATH%"
start "ArmorAV CLI" /D "%~dp0" cmd.exe /k "armorav --help"
goto END

:WEB
call :ENSURE_WEB
if errorlevel 1 goto MENU
start "" "%WEB_APP%"
goto END

:ENSURE_CLI
set "CLI_APP=%~dp0artifacts\win-x64\cli\armorav.exe"
if not exist "%CLI_APP%" goto BUILD_CLI
if not exist "%~dp0artifacts\win-x64\cli\armorav-version.txt" goto BUILD_CLI
findstr /X /C:"4.2.4" "%~dp0artifacts\win-x64\cli\armorav-version.txt" >nul || goto BUILD_CLI
if "%~dp0src\ArmorAV.Cli\Program.cs" newer "%CLI_APP%" goto BUILD_CLI
if "%~dp0src\ArmorAV.Cli\ArmorAV.Cli.csproj" newer "%CLI_APP%" goto BUILD_CLI
if "%~dp0src\ArmorAV.Core\ArmorAV.cs" newer "%CLI_APP%" goto BUILD_CLI
exit /b 0

:BUILD_CLI
call :CHECK_DOTNET
if errorlevel 1 exit /b 1
echo.
echo Preparing ArmorAV CLI. The first build can take several minutes.
dotnet publish ".\src\ArmorAV.Cli\ArmorAV.Cli.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ".\artifacts\win-x64\cli"
if errorlevel 1 (
  echo.
  echo ArmorAV CLI could not be built. Keep this window open and send the error text to support.
  pause
  exit /b 1
)
echo 4.2.4>"%~dp0artifacts\win-x64\cli\armorav-version.txt"
exit /b 0

:ENSURE_WEB
set "WEB_APP=%~dp0artifacts\win-x64\web\ArmorAV.Web.exe"
if not exist "%WEB_APP%" goto BUILD_WEB
if not exist "%~dp0artifacts\win-x64\web\armorav-web-version.txt" goto BUILD_WEB
findstr /X /C:"4.2.4" "%~dp0artifacts\win-x64\web\armorav-web-version.txt" >nul || goto BUILD_WEB
if "%~dp0src\ArmorAV.Web\Program.cs" newer "%WEB_APP%" goto BUILD_WEB
if "%~dp0src\ArmorAV.Web\wwwroot\index.html" newer "%WEB_APP%" goto BUILD_WEB
if "%~dp0src\ArmorAV.Web\wwwroot\styles.css" newer "%WEB_APP%" goto BUILD_WEB
if "%~dp0src\ArmorAV.Web\wwwroot\app.js" newer "%WEB_APP%" goto BUILD_WEB
if "%~dp0src\ArmorAV.Web\ArmorAV.Web.csproj" newer "%WEB_APP%" goto BUILD_WEB
if "%~dp0src\ArmorAV.Core\ArmorAV.cs" newer "%WEB_APP%" goto BUILD_WEB
exit /b 0

:BUILD_WEB
call :CHECK_DOTNET
if errorlevel 1 exit /b 1
echo.
echo Preparing ArmorAV Browser Console. The first build can take several minutes.
dotnet publish ".\src\ArmorAV.Web\ArmorAV.Web.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ".\artifacts\win-x64\web"
if errorlevel 1 (
  echo.
  echo ArmorAV Browser Console could not be built. Keep this window open and send the error text to support.
  pause
  exit /b 1
)
echo 4.2.4>"%~dp0artifacts\win-x64\web\armorav-web-version.txt"
exit /b 0

:CHECK_DOTNET
where dotnet >nul 2>nul
if not errorlevel 1 exit /b 0
echo.
echo .NET 8 SDK was not found.
echo Install the .NET 8 SDK from https://dotnet.microsoft.com/download/dotnet/8.0 and run this file again.
pause
exit /b 1

:END
endlocal
