#!/bin/sh
# Publishes a release every Psst installs on its own within ~6 hours.
# Usage: ./release.sh 1.1      Needs: gh (logged in), the signing key at ~/.config/psst/update.key
set -e
cd "$(dirname "$0")"
V="$1"
KEY="$HOME/.config/psst/update.key"
[ -n "$V" ] || { echo "usage: ./release.sh <version>"; exit 1; }
[ -f "$KEY" ] || { echo "missing signing key $KEY"; exit 1; }
git diff --quiet HEAD || { echo "commit your changes first"; exit 1; }

VERSION="$V" ./build.sh
Psst.app/Contents/MacOS/Psst --selftest
OUT=$(mktemp -d)
ditto -c -k --keepParent Psst.app "$OUT/Psst.zip"
Psst.app/Contents/MacOS/Psst --sign "$OUT/Psst.zip" "$KEY" > "$OUT/Psst.zip.sig"
echo "$V" > "$OUT/version.txt"  # only Psst 1.3.1 and older read this; newer copies take the version from the release tag

git push
gh release create "v$V" "$OUT/Psst.zip" "$OUT/Psst.zip.sig" "$OUT/version.txt" --title "Psst $V" --generate-notes
git fetch --tags  # the tag is made on GitHub; local builds read their version from it
rm -rf "$OUT"
