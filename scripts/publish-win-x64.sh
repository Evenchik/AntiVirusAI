#!/usr/bin/env sh
set -eu

if [ -x "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet" ]; then
  DOTNET="${DOTNET_ROOT:-$HOME/.dotnet}/dotnet"
elif command -v dotnet >/dev/null 2>&1; then
  DOTNET="$(command -v dotnet)"
else
  echo "dotnet SDK 8 is required. Run ./scripts/install-dotnet.sh first." >&2
  exit 1
fi

OUTPUT="artifacts/win-x64"
rm -rf "$OUTPUT"
"$DOTNET" publish src/ArmorAV.Cli/ArmorAV.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o "$OUTPUT/cli"
"$DOTNET" publish src/ArmorAV.Desktop/ArmorAV.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o "$OUTPUT/desktop"
printf 'CLI: %s\nDesktop: %s\n' "$OUTPUT/cli/armorav.exe" "$OUTPUT/desktop/ArmorAV.Desktop.exe"
