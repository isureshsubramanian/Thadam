#!/usr/bin/env bash
# One-time move of a single-file store and registry into the root-owned layout (ADR-009
# Decision 7). Run with sudo, with the collector stopped:
#
#   sudo scripts/migrate-store.sh [<old folder>] [<thadam-store binary>]
#
# The old folder defaults to the invoking user's ~/Library/Application Support/Thadam.
# Nothing in the old folder is changed or deleted: remove it yourself once the new folder
# verifies. Each step is printed before it runs.
set -euo pipefail

NEW="/Library/Application Support/Thadam"
STORE="$NEW/store"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run with sudo: the new folder is owned by root" >&2
    exit 2
fi
if [[ -z "${1:-}" && -z "${SUDO_USER:-}" ]]; then
    echo "give the old folder: sudo $0 <old folder>" >&2
    exit 2
fi
OLD="${1:-$(eval echo "~$SUDO_USER")/Library/Application Support/Thadam}"
BIN="${2:-$(cd "$(dirname "$0")/.." && pwd)/target/release/thadam-store}"

step() { printf '\n== %s\n' "$1"; }

step "check: collector stopped, old store present, new store absent"
if pgrep -x thadam-collector >/dev/null; then
    echo "thadam-collector is running; stop it first" >&2
    exit 2
fi
[[ -f "$OLD/events.db" ]] || { echo "no events.db in $OLD" >&2; exit 2; }
[[ -x "$BIN" ]] || { echo "no thadam-store binary at $BIN (cargo build --release)" >&2; exit 2; }
[[ ! -e "$STORE/catalog.db" ]] || { echo "$STORE already has a catalog" >&2; exit 2; }

step "create $STORE (root:wheel 0755)"
install -d -o root -g wheel -m 0755 "$NEW" "$STORE"

step "copy events.db into the store as its first segment, then verify the folder"
"$BIN" migrate "$OLD/events.db" "$STORE"

step "set owner root:wheel, folders 0755, files 0644"
chown -R root:wheel "$STORE"
find "$STORE" -type d -exec chmod 0755 {} +
find "$STORE" -type f -exec chmod 0644 {} +

if [[ -f "$OLD/registry.json" ]]; then
    step "copy registry.json (root:wheel 0644)"
    install -o root -g wheel -m 0644 "$OLD/registry.json" "$NEW/registry.json"
fi

shopt -s nullglob
pilots=("$OLD"/events-v1-*.db)
if (( ${#pilots[@]} )); then
    step "copy the v1 pilot store(s) to $STORE/archive (outside the catalog's chain)"
    install -d -o root -g wheel -m 0755 "$STORE/archive"
    for f in "${pilots[@]}"; do
        install -o root -g wheel -m 0644 "$f" "$STORE/archive/"
    done
fi

step "verify the new folder"
"$BIN" verify "$STORE"

printf '\nMigrated. Start the collector with:\n  --registry "%s" --store "%s"\n' \
    "$NEW/registry.json" "$STORE"
printf 'The old folder is unchanged: %s\n' "$OLD"
