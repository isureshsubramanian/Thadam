#!/usr/bin/env bash
# Local gate. Run before every commit; every step must pass.
set -euo pipefail
cd "$(dirname "$0")/.."
# Tests and builds send nothing to Microsoft.
export DOTNET_CLI_TELEMETRY_OPTOUT=1 TESTINGPLATFORM_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

step() { printf '\n== %s\n' "$1"; }

step "format"
cargo fmt --all -- --check

step "clippy (unwrap/expect denied outside tests)"
cargo clippy --workspace --all-targets -- -D warnings

step "tests"
cargo test --workspace

step "api: format, build (warnings as errors), tests"
# Run inside api/ so its global.json (SDK pin, test runner) applies.
(
    cd api
    dotnet format Thadam.slnx --verify-no-changes
    dotnet build Thadam.slnx -c Release --nologo -v quiet
    dotnet test --solution Thadam.slnx --no-progress
)

step "licence policy"
cargo deny check licenses bans sources

step "third-party notices up to date (licence policy for NuGet too)"
tmp="$(mktemp)"
out="$(mktemp)"
trap 'rm -f "$tmp" "$out"' EXIT
cargo about generate --fail about.hbs -o "$tmp"
node scripts/notices.mjs "$tmp" > "$out"
if ! cmp -s "$out" THIRD-PARTY-NOTICES.txt; then
    echo "THIRD-PARTY-NOTICES.txt is stale: run scripts/notices.sh"
    exit 1
fi

step "swift: no force unwrap, try! or as! outside tests"
find macos -name '*.swift' -not -path '*/Tests/*' -not -path '*/.build/*' -print0 \
    | xargs -0 perl scripts/swift-unwrap-check.pl

step "swift: extension tests and unsigned build"
if xcodebuild -version >/dev/null 2>&1; then
    swift test --package-path macos/ThadamNetKit
    xcodebuild -quiet -project macos/ThadamNet.xcodeproj -scheme ThadamNet \
        -destination 'platform=macOS,arch=arm64' -configuration Debug \
        -derivedDataPath target/xcode CODE_SIGNING_ALLOWED=NO build
else
    echo "Xcode not found: Swift tests and build skipped"
fi

step "product-name gate"
# The names themselves live in a local, uncommitted list so they never enter the source.
names="${THADAM_NAME_LIST:-scripts/.name-gate.local}"
if [[ ! -s "$names" ]]; then
    echo "missing name list: $names (one name per line)"
    exit 1
fi
if grep -rniwF -f "$names" --exclude-dir=.build --exclude-dir=bin --exclude-dir=obj --exclude=.name-gate.local crates/ macos/ api/ scripts/ README.md Cargo.toml; then
    echo "product names found in source (allowed only in adapters and the registry file)"
    exit 1
fi

printf '\nGate passed.\n'
