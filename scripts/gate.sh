#!/usr/bin/env bash
# Local gate. Run before every commit; every step must pass.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$1"; }

step "format"
cargo fmt --all -- --check

step "clippy (unwrap/expect denied outside tests)"
cargo clippy --workspace --all-targets -- -D warnings

step "tests"
cargo test --workspace

step "licence policy"
cargo deny check licenses bans sources

step "third-party notices up to date"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
cargo about generate --fail about.hbs -o "$tmp"
if ! cmp -s "$tmp" THIRD-PARTY-NOTICES.txt; then
    echo "THIRD-PARTY-NOTICES.txt is stale: run"
    echo "  cargo about generate --fail about.hbs -o THIRD-PARTY-NOTICES.txt"
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
if grep -rniwF -f "$names" --exclude-dir=.build crates/ macos/ README.md Cargo.toml; then
    echo "product names found in source (allowed only in adapters and the registry file)"
    exit 1
fi

printf '\nGate passed.\n'
