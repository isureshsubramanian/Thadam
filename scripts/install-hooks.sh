#!/usr/bin/env bash
# Builds, signs and installs the hook program and the tools' hook configuration (ADR-011).
# Asks for sudo.
#
# Signed with the same identity as the collector, so the collector can tell the installed
# hook from any other program that writes to its agent socket. The identity is chosen by SHA-1
# (see preflight.sh), never stored in the repo.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/preflight.sh

preflight_not_root
identity="$(preflight_identity "${THADAM_SIGNING_KIND:-development}")"
preflight_test_sign "$identity"

cargo build --release -q -p thadam-hook
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp target/release/thadam-hook "$tmp/"
codesign --force --sign "$identity" --identifier com.nerttiyana.thadam.hook \
    --options runtime --timestamp=none "$tmp/thadam-hook"
sudo "$tmp/thadam-hook" install-hooks "$@"
postflight_check "$tmp/thadam-hook" "/Library/Application Support/Thadam/bin/thadam-hook"
