#!/usr/bin/env bash
# Builds, signs and installs the API and dashboard (ADR-008, ADR-013 Decision 3). Asks for sudo
# to place the program in a root-owned folder; the API itself runs as you, from a launch agent.
#
# The program lives in /Library/Application Support/Thadam/app, so no program running as you
# can replace it; the collector accepts audit entries only from it. Your API data (password,
# keys, search index) stays in ~/Library/Application Support/Thadam/api. Install the collector
# first: the API writes its audit log through it.
#
# The first time, the API's old audit log (in your data folder) is copied into the collector's
# root-owned log; the old file is left as it is.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/preflight.sh

app="/Library/Application Support/Thadam/app"
collector="/Library/Application Support/Thadam/bin/thadam-collector"
data="$HOME/Library/Application Support/Thadam/api"
audit_socket="/var/run/thadam-audit/audit.sock"
audit_db="/Library/Application Support/Thadam/audit/audit.db"

preflight_not_root
if [[ ! -S "$audit_socket" ]]; then
    echo "The collector is not accepting audit entries ($audit_socket is missing)." >&2
    echo "Install or start the collector first: scripts/install-collector.sh" >&2
    exit 1
fi
identity="$(preflight_identity "${THADAM_SIGNING_KIND:-development}")"
preflight_test_sign "$identity"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
(cd web && npm ci --prefer-offline --no-audit --no-fund --silent && npx vite build --logLevel warn)
DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet publish api/src/Thadam.Api -c Release -r osx-arm64 --self-contained false \
    -o "$tmp/app" --nologo -v quiet
codesign --force --sign "$identity" --identifier com.nerttiyana.thadam.api \
    --options runtime --entitlements api/packaging/thadam-api.entitlements \
    --timestamp=none "$tmp/app/thadam-api"
# An unknown command prints the usage and exits 2 without touching any data.
rc=0
"$tmp/app/thadam-api" no-such-command >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 2 ]]; then
    echo "The signed API does not start (expected its usage message)." >&2
    exit 1
fi

# Stop the running API (old or new place) before its audit log changes hands.
for old in "$data/app/thadam-api" "$app/thadam-api"; do
    if [[ -x "$old" ]]; then
        "$old" uninstall >/dev/null 2>&1 || true
    fi
done
if [[ -f "$data/audit.db" ]]; then
    # Refused (and harmless) once the system log has entries: the copy happens once.
    sudo "$collector" import-audit --from "$data/audit.db" --audit-db "$audit_db" || true
fi

sudo rm -rf "$app.new"
sudo ditto "$tmp/app" "$app.new"
sudo chown -R root:wheel "$app.new"
sudo chmod -R go-w "$app.new"
sudo rm -rf "$app.old"
if [[ -d "$app" ]]; then
    sudo mv "$app" "$app.old"
fi
sudo mv "$app.new" "$app"
sudo rm -rf "$app.old"

"$app/thadam-api" install --audit-socket "$audit_socket" --audit-db "$audit_db"
postflight_check "$tmp/app/thadam-api" "$app/thadam-api"
if [[ -d "$data/app" ]]; then
    rm -rf "$data/app"
    echo "Removed the previous copy of the API from your data folder."
fi
