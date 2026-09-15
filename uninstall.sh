#!/usr/bin/env bash
# ==============================================================================
# Uninstaller for Cachy Security Suite
# ==============================================================================
set -e

COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[1;31m"
COLOR_BLUE="\033[1;34m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_BLUE}Deinstallation von Cachy Security Suite...${COLOR_RESET}"

if [ "$1" = "--user" ] || [ "$EUID" -ne 0 ]; then
    PREFIX="$HOME/.local"
else
    PREFIX="/usr"
fi

rm -rf "$PREFIX/share/cachy-security-suite"
rm -rf "$PREFIX/share/aur-scanner-gui"
rm -f "$PREFIX/bin/cachy-security-suite"
rm -f "$PREFIX/bin/aur-scanner-gui"
rm -f "$PREFIX/share/applications/cachy-security-suite.desktop"
rm -f "$PREFIX/share/applications/aur-scanner-gui.desktop"
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/aur-scanner.svg"
rm -f "$PREFIX/share/icons/hicolor/256x256/apps/aur-scanner.png"

if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true
fi

echo -e "${COLOR_GREEN}✓ Cachy Security Suite wurde erfolgreich entfernt.${COLOR_RESET}"
