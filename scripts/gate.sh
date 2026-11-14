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

step "web: install from the lock file, types, lint, tests, build"
# Before the API: its build copies web/dist next to it, and the notices read the bundle list.
(
    cd web
    npm ci --prefer-offline --no-audit --no-fund
    npm run --silent typecheck
    npm run --silent lint
    npm test --silent
    npx vite build --logLevel warn
)

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

step "third-party notices up to date (licence policy for NuGet and npm too)"
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
hits="$(grep -rniwF -f "$names" --exclude-dir=.build --exclude-dir=bin --exclude-dir=obj --exclude-dir=node_modules \
    --exclude-dir=dist --exclude=.name-gate.local crates/ macos/ api/ web/ scripts/ README.md Cargo.toml || true)"
# Two exceptions. The agent adapters (crates/thadam-hook/src/adapters/), the only place a
# tool may be named (project rule 6, ADR-011 Decision 2). And data the language requires:
# in .css files, the declaration of CSS's pointer-shape property with the values `pointer`
# or `default`; it is removed from the line before the line is checked again, so any other
# use of a name on it still fails.
hits="$(printf '%s\n' "$hits" | perl -e '
    open my $f, "<", shift or die; chomp(my @n = grep { /\S/ } <$f>);
    my $re = join "|", map { quotemeta } @n;
    while (<STDIN>) {
        my ($file, $text) = /^([^:]+):\d+:(.*)$/ or next;
        next if $file =~ m{^crates/thadam-hook/src/adapters/};
        $text =~ s/\b(?:c)ursor:\s*(?:pointer|default)\b//gi if $file =~ /\.css$/;
        print if $text =~ /\b(?:$re)\b/i;
    }' "$names")"
if [[ -n "$hits" ]]; then
    printf '%s\n' "$hits"
    echo "product names found in source (allowed only in adapters and the registry file)"
    exit 1
fi

printf '\nGate passed.\n'
