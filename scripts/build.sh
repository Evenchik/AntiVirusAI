#!/usr/bin/env sh
# Restores, builds and runs ArmorAV's dependency-free smoke tests.
set -eu

if [ -x "${DOTNET_ROOT:-$HOME/.dotnet}/dotnet" ]; then
  DOTNET="${DOTNET_ROOT:-$HOME/.dotnet}/dotnet"
elif command -v dotnet >/dev/null 2>&1; then
  DOTNET="$(command -v dotnet)"
else
  echo "dotnet SDK 8 is required. Run ./scripts/install-dotnet.sh first." >&2
  exit 1
fi

"$DOTNET" restore ArmorAV.sln
"$DOTNET" build ArmorAV.sln --configuration Release --no-restore
"$DOTNET" run --project tests/ArmorAV.SmokeTests/ArmorAV.SmokeTests.csproj --configuration Release --no-build
