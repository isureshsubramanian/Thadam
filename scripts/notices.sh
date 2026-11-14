#!/usr/bin/env bash
# Regenerates THIRD-PARTY-NOTICES.txt: cargo-about for Rust, then scripts/notices.mjs for the
# API's NuGet packages. The gate fails when the committed file differs from this output.
set -euo pipefail
cd "$(dirname "$0")/.."
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
(cd api && dotnet restore Thadam.slnx --nologo -v quiet)
cargo about generate --fail about.hbs -o "$tmp"
node scripts/notices.mjs "$tmp" > THIRD-PARTY-NOTICES.txt
echo "THIRD-PARTY-NOTICES.txt regenerated"
