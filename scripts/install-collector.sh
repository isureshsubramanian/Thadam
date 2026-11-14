#!/usr/bin/env bash
# Builds, signs and installs the collector as a launch daemon (ADR-010). Asks for sudo.
#
# Signing with a stable identity keeps the Full Disk Access grant across updates (macOS ties
# the grant to the code signature). The identity is read from the keychain, never stored in
# the repo; THADAM_SIGNING_IDENTITY overrides it.
set -euo pipefail
cd "$(dirname "$0")/.."

identity="${THADAM_SIGNING_IDENTITY:-$(security find-identity -v -p codesigning \
    | awk -F'"' '/Apple Development/ { print $2; exit }')}"
if [[ -z "$identity" ]]; then
    echo "no Apple Development signing identity in the keychain"
    exit 1
fi

cargo build --release -q -p thadam-collector
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp target/release/thadam-collector "$tmp/"
codesign --force --sign "$identity" --identifier com.nerttiyana.thadam.collector \
    --options runtime --timestamp=none "$tmp/thadam-collector"
sudo "$tmp/thadam-collector" install "$@"
