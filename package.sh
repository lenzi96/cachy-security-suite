#!/usr/bin/env bash
# ==============================================================================
# Script to create a distributable release archive (tar.gz)
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.3.0"
DIST_DIR="$DIR/dist"
ARCHIVE_NAME="cachy-security-suite-v${VERSION}"
TARGET_TAR="$DIST_DIR/${ARCHIVE_NAME}.tar.gz"

echo "Erstelle Release-Archiv: ${TARGET_TAR}..."
mkdir -p "$DIST_DIR"

# Clean any pycache
find "$DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Create tarball from parent directory so files unpack cleanly
tar -czf "$TARGET_TAR" \
    --exclude='dist' \
    --exclude='.git' \
    --exclude='*.pkg.tar.zst' \
    --exclude='src' \
    --exclude='pkg' \
    --transform "s,^$DIR,$ARCHIVE_NAME," \
    -C "$(dirname "$DIR")" \
    "$(basename "$DIR")"

# Also provide compatibility link
ln -sf "${ARCHIVE_NAME}.tar.gz" "$DIST_DIR/aur-scanner-gui-v${VERSION}.tar.gz" 2>/dev/null || true

echo "✓ Erfolgreich erstellt: $TARGET_TAR ($(du -h "$TARGET_TAR" | cut -f1))"
echo "Dieses Archiv kannst du jetzt an Freunde oder andere Arch-/CachyOS-Nutzer weitergeben!"
