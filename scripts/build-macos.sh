#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
configuration=${1:-release}
case "$configuration" in
    debug|release) ;;
    *) echo "Usage: $0 [debug|release]" >&2; exit 2 ;;
esac

swift build -c "$configuration" --product MySafeAI
bin_dir=$(swift build -c "$configuration" --show-bin-path)
icon_build=$(mktemp -d)
temporary_binary=
trap 'rm -rf "$icon_build"; if [ -n "$temporary_binary" ]; then rm -f "$temporary_binary"; fi' EXIT
swiftc Sources/MySafeAI/BrandMark.swift scripts/generate-app-icon.swift -o "$icon_build/generate-app-icon"
"$icon_build/generate-app-icon" "$icon_build/AppIcon.iconset"
iconutil -c icns "$icon_build/AppIcon.iconset" -o "$icon_build/AppIcon.icns"

app="$PWD/dist/MySafeAI.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
ditto "$bin_dir/MySafeAI_NetworkDiagnostics.bundle" "$app/Contents/Resources/MySafeAI_NetworkDiagnostics.bundle"
temporary_binary=$(mktemp "$app/Contents/MacOS/.MySafeAI.XXXXXX")
install -m 755 "$bin_dir/MySafeAI" "$temporary_binary"
mv -f "$temporary_binary" "$app/Contents/MacOS/MySafeAI"
(cd portable && CGO_ENABLED=0 go build -trimpath -o "$app/Contents/MacOS/mysafeai-browser-host" ./cmd/browser-host)
codesign --force --sign - "$app/Contents/MacOS/mysafeai-browser-host"
install -m 644 scripts/Info.plist "$app/Contents/Info.plist"
install -m 644 "$icon_build/AppIcon.icns" "$app/Contents/Resources/AppIcon.icns"
install -m 644 "$icon_build/AppIcon.iconset/icon_256x256.png" "$PWD/dist/MySafeAI-logo.png"
codesign --force --sign - "$app"
touch "$app" # Invalidate Finder's cached icon when rebuilding in place.
printf '%s\n' "$app"
