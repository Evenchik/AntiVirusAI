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

exec "$DOTNET" run --project src/ArmorAV.Cli/ArmorAV.Cli.csproj -- "$@"
