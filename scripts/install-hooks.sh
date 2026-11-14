#!/usr/bin/env bash
# Builds, signs and installs the hook program and the tools' hook configuration (ADR-011).
# Asks for sudo.
#
# Signed with the same identity as the collector, so the collector can tell the installed
# hook from any other program that writes to its agent socket. The identity is read from
# the keychain, never stored in the repo; THADAM_SIGNING_IDENTITY overrides it.
set -euo pipefail
cd "$(dirname "$0")/.."

identity="${THADAM_SIGNING_IDENTITY:-$(security find-identity -v -p codesigning \
    | awk -F'"' '/Apple Development/ { print $2; exit }')}"
if [[ -z "$identity" ]]; then
    echo "no Apple Development signing identity in the keychain"
    exit 1
fi

cargo build --release -q -p thadam-hook
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp target/release/thadam-hook "$tmp/"
codesign --force --sign "$identity" --identifier com.nerttiyana.thadam.hook \
    --options runtime --timestamp=none "$tmp/thadam-hook"
sudo "$tmp/thadam-hook" install-hooks "$@"
