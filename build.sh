#!/bin/sh
# Builds Psst.app (universal: Apple Silicon + Intel, macOS 12+). Needs Xcode Command Line Tools.
set -e
cd "$(dirname "$0")"
APP=Psst.app
# Version: $VERSION (release.sh sets it), else the latest git tag, else 0.
VERSION=${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed "s/^v//")}
VERSION=${VERSION:-0}
TMP=$(mktemp -d)
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -target "$arch-apple-macos12" main.swift -o "$TMP/psst-$arch"
done
lipo -create "$TMP/psst-arm64" "$TMP/psst-x86_64" -output "$APP/Contents/MacOS/Psst"
rm -rf "$TMP"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>local.psst</string>
  <key>CFBundleName</key><string>Psst</string>
  <key>CFBundleExecutable</key><string>Psst</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSUIElement</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>Psst finds classmates running Psst on this network.</string>
  <key>NSBonjourServices</key><array><string>_psst._tcp</string></array>
</dict></plist>
EOF

codesign --force -s - "$APP"
du -sh "$APP"
