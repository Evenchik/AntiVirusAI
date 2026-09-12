#!/usr/bin/env sh
# Installs the .NET 8 SDK for the current user; no root access is required.
set -eu

DOTNET_DIR="${DOTNET_ROOT:-$HOME/.dotnet}"
INSTALLER="${TMPDIR:-/tmp}/dotnet-install.sh"

if [ -x "$DOTNET_DIR/dotnet" ]; then
  echo ".NET is already installed at $DOTNET_DIR"
else
  mkdir -p "$DOTNET_DIR"
  curl --fail --location --retry 3 https://dot.net/v1/dotnet-install.sh -o "$INSTALLER"
  sh "$INSTALLER" --channel 8.0 --install-dir "$DOTNET_DIR" --no-path
fi

printf '\nAdd this to the current shell if needed:\n'
printf '  export DOTNET_ROOT="%s"\n  export PATH="$DOTNET_ROOT:$PATH"\n\n' "$DOTNET_DIR"
"$DOTNET_DIR/dotnet" --info
