#!/usr/bin/env bash
# Regenerates the app icon (macos/App/AppIcon.icns) and the dashboard favicon
# (web/public/favicon.svg) from the one drawing, macos/Icon/AppIcon.svg. OS tools only.
# Run it after changing the drawing and commit the results.
set -euo pipefail
cd "$(dirname "$0")/.."
src=macos/Icon/AppIcon.svg
set_dir="$(mktemp -d)/AppIcon.iconset"
trap 'rm -rf "$(dirname "$set_dir")"' EXIT
mkdir -p "$set_dir"
for size in 16 32 128 256 512; do
    swift macos/Icon/render.swift "$src" "$set_dir/icon_${size}x${size}.png" "$size"
    swift macos/Icon/render.swift "$src" "$set_dir/icon_${size}x${size}@2x.png" "$((size * 2))"
done
iconutil --convert icns --output macos/App/AppIcon.icns "$set_dir"
cp "$src" web/public/favicon.svg
echo "Wrote macos/App/AppIcon.icns and web/public/favicon.svg"
