# shellcheck shell=bash
# Checks shared by the install and packaging scripts (ADR-013 Decision 5). Sourced, not run.
#
# Signing identities are chosen by SHA-1, never by name: two certificates can share a name.
# The SHA-1 comes from THADAM_SIGNING_IDENTITY, or from scripts/signing.local (git-ignored,
# lines such as "development=<SHA-1>"), or, for "development" only, from the keychain when it
# holds exactly one Apple Development identity.

preflight_not_root() {
    if [[ "$(id -u)" == 0 ]]; then
        echo "Run this as yourself, not with sudo: it asks for sudo only for the install step." >&2
        echo "(Building as root leaves root-owned files in target/ that break later builds.)" >&2
        exit 1
    fi
}

# preflight_identity <development|application|installer>: prints the SHA-1 to sign with.
preflight_identity() {
    local kind="$1" policy="codesigning" label sha
    case "$kind" in
        development) label="Apple Development" ;;
        application) label="Developer ID Application" ;;
        installer) label="Developer ID Installer"; policy="basic" ;;
        *) echo "unknown identity kind: $kind" >&2; return 1 ;;
    esac
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    sha="${THADAM_SIGNING_IDENTITY:-}"
    if [[ -z "$sha" && -f "$here/signing.local" ]]; then
        sha="$(awk -F= -v k="$kind" '$1 == k { print $2 }' "$here/signing.local" | tr -d '[:space:]')"
    fi
    local found
    found="$(security find-identity -v -p "$policy" | awk -v l="$label" 'index($0, "\"" l ":") { print $2 }')"
    if [[ -z "$sha" ]]; then
        local n
        n="$(printf '%s\n' "$found" | grep -c . || true)"
        if [[ "$kind" == development && "$n" == 1 ]]; then
            printf '%s\n' "$found"
            return 0
        fi
        if [[ "$n" == 0 ]]; then
            echo "No \"$label\" identity in the keychain." >&2
        else
            echo "$n \"$label\" identities in the keychain; choose one by SHA-1:" >&2
            security find-identity -v -p "$policy" | grep "\"$label:" | sed 's/^/    /' >&2
            echo "then add \"$kind=<SHA-1>\" to scripts/signing.local (git-ignored)." >&2
        fi
        return 1
    fi
    if ! printf '%s\n' "$found" | grep -qix "$sha"; then
        echo "The chosen $kind identity ($sha) is not a valid \"$label\" identity in the keychain." >&2
        return 1
    fi
    printf '%s\n' "$sha"
}

# preflight_test_sign <SHA-1>: signs a throwaway file, so a keychain problem shows up before
# anything is built, with the fix instead of the raw error.
preflight_test_sign() {
    local sha="$1" dir out
    dir="$(mktemp -d)"
    cp /usr/bin/true "$dir/probe"
    if ! out="$(codesign --force --sign "$sha" --timestamp=none "$dir/probe" 2>&1)"; then
        rm -rf "$dir"
        if [[ "$out" == *errSecInternalComponent* ]]; then
            echo "Signing failed: the keychain did not let codesign use the private key." >&2
            echo "Fix: run this in a Terminal window on the Mac's own desktop (not over SSH or" >&2
            echo "from an IDE), unlock the login keychain (security unlock-keychain), and when" >&2
            echo "macOS asks for the key, choose Always Allow." >&2
        else
            echo "Signing failed: $out" >&2
        fi
        return 1
    fi
    rm -rf "$dir"
}

# postflight_check <built> <installed>: the installed file is the one just built and signed.
postflight_check() {
    local built="$1" installed="$2"
    if ! cmp -s "$built" "$installed"; then
        echo "Installed file differs from the one just built: $installed" >&2
        return 1
    fi
    echo "Installed $installed"
    codesign -dvv "$installed" 2>&1 | awk -F= '/^(Identifier|TeamIdentifier)=/ { print "    " $0 } /^Authority=/ && !seen++ { print "    " $0 }'
}
