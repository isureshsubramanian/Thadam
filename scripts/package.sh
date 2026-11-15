#!/usr/bin/env bash
# Builds the signed, notarized installer package (ADR-013 Decision 4): the collector, the hook,
# the API with the dashboard, and the network extension app, all signed with Developer ID and
# the hardened runtime, in one package signed with Developer ID Installer. Its postinstall
# runs the same steps as the install scripts.
#
#   scripts/package.sh [--without-network] [--no-notarize]
#
# Identities are chosen by SHA-1 (see preflight.sh: "application" and "installer" in
# scripts/signing.local). Notarization uses a notarytool keychain profile, named by
# THADAM_NOTARY_PROFILE (default "thadam-notary"); its secret stays in the keychain.
# --no-notarize builds a local test package (no secure timestamps, not notarized).
# --without-network leaves the network extension out. With it, the two Developer ID
# provisioning profiles, named after the bundle ids, must be installed for Xcode.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/preflight.sh

network=1
notarize=1
for arg in "$@"; do
    case "$arg" in
        --without-network) network=0 ;;
        --no-notarize) notarize=0 ;;
        *) echo "usage: scripts/package.sh [--without-network] [--no-notarize]" >&2; exit 2 ;;
    esac
done

preflight_not_root
app_id="$(preflight_identity application)"
installer_id="$(preflight_identity installer)"
preflight_test_sign "$app_id"
profile="${THADAM_NOTARY_PROFILE:-thadam-notary}"
if [[ "$notarize" == 1 ]] && ! xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1; then
    echo "No notarytool keychain profile \"$profile\". Create it once with:" >&2
    echo "    xcrun notarytool store-credentials $profile --apple-id <id> --team-id <team>" >&2
    echo "(it asks for an app-specific password and keeps it in the keychain), or pass --no-notarize." >&2
    exit 1
fi
timestamp=(--timestamp)
[[ "$notarize" == 0 ]] && timestamp=(--timestamp=none)

version="$(awk -F'"' '/^version *=/ { print $2; exit }' Cargo.toml)"
out="target/package"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
root="$stage/root"
thadam="$root/Library/Application Support/Thadam"
mkdir -p "$thadam/bin" "$out"

sign() { # sign <file> <identifier> [extra codesign args]
    local file="$1" id="$2"
    shift 2
    codesign --force --sign "$app_id" --identifier "$id" --options runtime "${timestamp[@]}" "$@" "$file"
}

echo "== Rust: collector and hook"
cargo build --release -q -p thadam-collector -p thadam-hook
cp target/release/thadam-collector target/release/thadam-hook "$thadam/bin/"
sign "$thadam/bin/thadam-collector" com.nerttiyana.thadam.collector
sign "$thadam/bin/thadam-hook" com.nerttiyana.thadam.hook

echo "== API and dashboard"
(cd web && npm ci --prefer-offline --no-audit --no-fund --silent && npx vite build --logLevel warn)
DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    dotnet publish api/src/Thadam.Api -c Release -r osx-arm64 --self-contained false \
    -o "$thadam/app" --nologo -v quiet
# Every Mach-O file must carry the Developer ID signature for notarization.
while IFS= read -r -d '' f; do
    if [[ "$f" != "$thadam/app/thadam-api" ]] && file -b "$f" | grep -q Mach-O; then
        sign "$f" "com.nerttiyana.thadam.api.$(basename "$f")"
    fi
done < <(find "$thadam/app" -type f -print0)
sign "$thadam/app/thadam-api" com.nerttiyana.thadam.api --entitlements api/packaging/thadam-api.entitlements
rc=0
"$thadam/app/thadam-api" no-such-command >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 2 ]]; then
    echo "The signed API does not start (expected its usage message)." >&2
    exit 1
fi

if [[ "$network" == 1 ]]; then
    echo "== Network extension app"
    # Manual signing with the Developer ID profiles: the automatic development profiles do not
    # carry the "-systemextension" entitlement values. Each profile is named after its
    # target's bundle id and must be installed in Xcode's profile folder.
    xcodebuild -quiet -project macos/ThadamNet.xcodeproj -scheme ThadamNet -configuration Release \
        -archivePath "$stage/ThadamNet.xcarchive" archive \
        THADAM_NE_ENTITLEMENT_SUFFIX=-systemextension \
        CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$app_id" \
        'PROVISIONING_PROFILE_SPECIFIER=$(PRODUCT_BUNDLE_IDENTIFIER)'
    cat > "$stage/export.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>method</key><string>developer-id</string>
    <key>signingStyle</key><string>manual</string>
    <key>signingCertificate</key><string>$app_id</string>
    <key>provisioningProfiles</key><dict>
        <key>com.nerttiyana.thadam.net</key><string>com.nerttiyana.thadam.net</string>
        <key>com.nerttiyana.thadam.net.filter</key><string>com.nerttiyana.thadam.net.filter</string>
    </dict>
</dict></plist>
PLIST
    xcodebuild -quiet -exportArchive -archivePath "$stage/ThadamNet.xcarchive" \
        -exportOptionsPlist "$stage/export.plist" -exportPath "$stage/export"
    mkdir -p "$root/Applications"
    ditto "$stage/export/ThadamNet.app" "$root/Applications/ThadamNet.app"
fi

echo "== Package"
# Extended attributes (provenance, quarantine) would otherwise ride along as "._" entries.
xattr -cr "$root"
mkdir -p "$stage/scripts"
cp scripts/package/postinstall "$stage/scripts/"
pkgbuild --analyze --root "$root" "$stage/components.plist" >/dev/null
# The app must land in /Applications, not wherever a copy with the same id happens to be.
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$stage/components.plist" 2>/dev/null || true
pkgbuild --root "$root" --component-plist "$stage/components.plist" --scripts "$stage/scripts" \
    --identifier com.nerttiyana.thadam --version "$version" --install-location / \
    --ownership recommended "$stage/component.pkg" >/dev/null
pkg="$out/Thadam-$version.pkg"
productbuild --package "$stage/component.pkg" --sign "$installer_id" "${timestamp[@]}" "$pkg" >/dev/null

if [[ "$notarize" == 1 ]]; then
    echo "== Notarize (waits for Apple)"
    xcrun notarytool submit "$pkg" --keychain-profile "$profile" --wait
    xcrun stapler staple "$pkg"
    xcrun stapler validate "$pkg"
    spctl --assess --type install -vv "$pkg"
else
    pkgutil --check-signature "$pkg" | sed -n '1,4p'
    echo "Local test package (not notarized): Gatekeeper will refuse it on another Mac."
fi
echo "Built $pkg"
