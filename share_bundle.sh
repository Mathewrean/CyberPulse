#!/usr/bin/env bash
# CyberPulse Share Bundle Generator
# Packages the complete application into a clean distributable zip/tar for sharing with other users

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PARENT="$(dirname "$DIR")"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BUNDLE_NAME="CyberPulse_Suite_$TIMESTAMP"
DIST_DIR="$PARENT/$BUNDLE_NAME"
ZIP_FILE="$PARENT/CyberPulse_Distribution.zip"
TAR_FILE="$PARENT/CyberPulse_Distribution.tar.gz"

echo "=========================================================="
echo "  CyberPulse Bundle Packager"
echo "=========================================================="
echo "Source Directory: $DIR"
echo "Creating staging directory: $DIST_DIR"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Copy core codebase excluding runtime databases, logs, and cache
rsync -av --exclude '__pycache__' \
          --exclude '*.pyc' \
          --exclude '*.pid' \
          --exclude '*.log' \
          --exclude 'data/*.db-journal' \
          --exclude '.git' \
          "$DIR/" "$DIST_DIR/"

echo "Generating distribution zip and tar.gz archives..."
cd "$PARENT"
tar -czf "$TAR_FILE" "$BUNDLE_NAME"
if which zip > /dev/null 2>&1; then
    zip -rq "$ZIP_FILE" "$BUNDLE_NAME"
    echo "[+] Created: $ZIP_FILE"
fi

rm -rf "$DIST_DIR"
echo "[+] Created: $TAR_FILE"
echo ""
echo "Shareable archives created on Desktop:"
ls -lh "$PARENT/CyberPulse_Distribution"*
echo "=========================================================="
