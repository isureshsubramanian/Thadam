#!/usr/bin/env bash
# Builds, signs and installs the collector as a launch daemon (ADR-010). Asks for sudo.
#
# Signing with a stable identity keeps the Full Disk Access grant across updates (macOS ties
# the grant to the code signature). The identity is chosen by SHA-1 (see preflight.sh), never
# stored in the repo.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/preflight.sh

preflight_not_root
identity="$(preflight_identity "${THADAM_SIGNING_KIND:-development}")"
preflight_test_sign "$identity"

cargo build --release -q -p thadam-collector
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp target/release/thadam-collector "$tmp/"
codesign --force --sign "$identity" --identifier com.nerttiyana.thadam.collector \
    --options runtime --timestamp=none "$tmp/thadam-collector"
sudo "$tmp/thadam-collector" install "$@"
postflight_check "$tmp/thadam-collector" "/Library/Application Support/Thadam/bin/thadam-collector"
