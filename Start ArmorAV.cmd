@echo off
setlocal
cd /d "%~dp0"
set "APP=%~dp0artifacts\win-x64\desktop\ArmorAV.Desktop.exe"
if exist "%APP%" (
  start "" "%APP%"
  exit /b 0
)
where dotnet >nul 2>nul
if errorlevel 1 (
  echo .NET 8 SDK was not found.
  echo Install the .NET 8 SDK from https://dotnet.microsoft.com/download/dotnet/8.0 and run this file again.
  pause
  exit /b 1
)
echo Preparing ArmorAV. The first launch can take a few minutes.
dotnet publish ".\src\ArmorAV.Desktop\ArmorAV.Desktop.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ".\artifacts\win-x64\desktop"
if errorlevel 1 (
  echo.
  echo ArmorAV could not be built. Keep this window open and send the error text to support.
  pause
  exit /b 1
)
start "" "%APP%"
