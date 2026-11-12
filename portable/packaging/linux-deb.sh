#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "$#" -ne 2 ]; then
    echo "Usage: linux-deb.sh BINARY OUTPUT.deb" >&2
    exit 64
fi

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/applications"     "$root/usr/share/icons/hicolor/48x48/apps" "$root/usr/share/doc/mysafeai"
arch=$(dpkg --print-architecture)
cat > "$root/DEBIAN/control" <<CONTROL
Package: mysafeai
Version: 0.3.0
Architecture: $arch
Maintainer: MySafeAI contributors <36034823+in-devp@users.noreply.github.com>
Section: net
Priority: optional
Depends: iproute2, libgtk-4-1, libwebkitgtk-6.0-4, glib-networking
Homepage: https://github.com/in-devp/MySafeAI
Description: Local process protection for VPN and direct connections
 MySafeAI verifies external IP addresses and pauses protected apps until the
 connection is approved.
CONTROL
install -m 755 "$1" "$root/usr/bin/mysafeai"
install -m 644 packaging/app.mysafeai.desktop.desktop "$root/usr/share/applications/"
install -m 644 web/tray.png "$root/usr/share/icons/hicolor/48x48/apps/app.mysafeai.desktop.png"
install -m 644 ../LICENSE "$root/usr/share/doc/mysafeai/copyright"
dpkg-deb --root-owner-group --build "$root" "$2"
