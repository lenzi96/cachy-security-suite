#!/usr/bin/env bash
# ==============================================================================
# Installer for Cachy Security Suite
# Can be run as:
#   ./install.sh --user     (Installs to ~/.local, no root/sudo needed)
#   sudo ./install.sh       (Installs system-wide to /usr)
# ==============================================================================
set -e

COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[1;31m"
COLOR_BLUE="\033[1;34m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_BLUE}====================================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}   Cachy Security Suite - Installationsprogramm     ${COLOR_RESET}"
echo -e "${COLOR_BLUE}====================================================${COLOR_RESET}\n"

# Determine install prefix & options
INSTALL_USER=false
WITH_POLKIT=false
NO_POLKIT=false

for arg in "$@"; do
    case "$arg" in
        --user)
            INSTALL_USER=true
            ;;
        --with-polkit|--setup-polkit)
            WITH_POLKIT=true
            ;;
        --no-polkit|--without-polkit)
            NO_POLKIT=true
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    INSTALL_USER=true
fi

if [ "$INSTALL_USER" = true ]; then
    PREFIX="$HOME/.local"
    BIN_DIR="$PREFIX/bin"
    SHARE_DIR="$PREFIX/share/cachy-security-suite"
    APP_DIR="$PREFIX/share/applications"
    ICON_DIR="$PREFIX/share/icons/hicolor/scalable/apps"
    echo -e "Installationsmodus: ${COLOR_YELLOW}Benutzerverzeichnis (${PREFIX})${COLOR_RESET}"
else
    PREFIX="/usr"
    BIN_DIR="$PREFIX/bin"
    SHARE_DIR="$PREFIX/share/cachy-security-suite"
    APP_DIR="$PREFIX/share/applications"
    ICON_DIR="$PREFIX/share/icons/hicolor/scalable/apps"
    echo -e "Installationsmodus: ${COLOR_GREEN}Systemweit (${PREFIX})${COLOR_RESET}"
fi

# 1. Dependency checks
echo -e "\n${COLOR_BLUE}[1/5] Prüfe System-Abhängigkeiten...${COLOR_RESET}"

MISSING_DEPS=0

if ! command -v python3 &>/dev/null; then
    echo -e "${COLOR_RED}✗ Python 3 ist nicht installiert!${COLOR_RESET}"
    MISSING_DEPS=1
else
    echo -e "${COLOR_GREEN}✓ Python 3 gefunden:${COLOR_RESET} $(python3 --version)"
fi

if ! python3 -c "import PyQt6" &>/dev/null; then
    echo -e "${COLOR_YELLOW}⚠ PyQt6 (python-pyqt6) ist noch nicht installiert.${COLOR_RESET}"
    echo -e "  Installation unter Arch Linux: ${COLOR_GREEN}sudo pacman -S python-pyqt6${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ PyQt6 ist verfügbar.${COLOR_RESET}"
fi

if ! command -v aur-scan &>/dev/null; then
    echo -e "${COLOR_YELLOW}⚠ 'aur-scan' (aur-scanner) wurde noch nicht im PATH gefunden.${COLOR_RESET}"
    echo -e "  Installation via AUR: ${COLOR_GREEN}yay -S aur-scanner${COLOR_RESET} oder ${COLOR_GREEN}paru -S aur-scanner${COLOR_RESET}"
else
    echo -e "${COLOR_GREEN}✓ aur-scan gefunden:${COLOR_RESET} $(aur-scan --version 2>/dev/null || echo 'installiert')"
fi

# 2. Creating target directories
echo -e "\n${COLOR_BLUE}[2/5] Erstelle Zielverzeichnisse...${COLOR_RESET}"
mkdir -p "$BIN_DIR" "$SHARE_DIR" "$APP_DIR" "$ICON_DIR"

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 3. Copying files
echo -e "\n${COLOR_BLUE}[3/5] Kopiere Anwendungsdateien...${COLOR_RESET}"
cp -r "$SOURCE_DIR/aur_scanner_gui" "$SHARE_DIR/"
cp "$SOURCE_DIR/main.py" "$SHARE_DIR/"
chmod +x "$SHARE_DIR/main.py"
if [ -f "$SOURCE_DIR/setup-polkit.sh" ]; then
    cp "$SOURCE_DIR/setup-polkit.sh" "$SHARE_DIR/"
    chmod +x "$SHARE_DIR/setup-polkit.sh"
fi

# Copy Icons
mkdir -p "$PREFIX/share/icons/hicolor/256x256/apps" "$PREFIX/share/icons/hicolor/scalable/apps"
if [ -f "$SOURCE_DIR/resources/aur-scanner.svg" ]; then
    cp "$SOURCE_DIR/resources/aur-scanner.svg" "$PREFIX/share/icons/hicolor/scalable/apps/aur-scanner.svg"
fi
if [ -f "$SOURCE_DIR/resources/aur-scanner-256.png" ]; then
    cp "$SOURCE_DIR/resources/aur-scanner-256.png" "$PREFIX/share/icons/hicolor/256x256/apps/aur-scanner.png"
fi
if [ -d "$SOURCE_DIR/resources" ]; then
    mkdir -p "$SHARE_DIR/resources"
    cp -r "$SOURCE_DIR/resources/"* "$SHARE_DIR/resources/"
fi

# Create launcher executable
cat <<EOF > "$BIN_DIR/cachy-security-suite"
#!/usr/bin/env bash
export PYTHONPATH="$SHARE_DIR:\$PYTHONPATH"
exec python3 "$SHARE_DIR/main.py" "\$@"
EOF
chmod +x "$BIN_DIR/cachy-security-suite"

# Compatibility symlink/launcher
ln -sf "$BIN_DIR/cachy-security-suite" "$BIN_DIR/aur-scanner-gui" 2>/dev/null || cp "$BIN_DIR/cachy-security-suite" "$BIN_DIR/aur-scanner-gui"

# Register module path in Python site-packages (.pth) so python3 -m aur_scanner_gui works anywhere
if [ "$INSTALL_USER" = true ]; then
    USER_SITE=$(python3 -c "import site; print(site.getusersitepackages())" 2>/dev/null || true)
    if [ -n "$USER_SITE" ]; then
        mkdir -p "$USER_SITE" 2>/dev/null || true
        echo "$SHARE_DIR" > "$USER_SITE/cachy-security-suite.pth" 2>/dev/null || true
    fi
else
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
    if [ -n "$PY_VER" ]; then
        SYS_SITE="/usr/lib/python${PY_VER}/site-packages"
        if [ -d "$SYS_SITE" ]; then
            echo "$SHARE_DIR" > "$SYS_SITE/cachy-security-suite.pth" 2>/dev/null || true
        fi
    fi
fi

# 4. Polkit & Sudoers Berechtigungen
echo -e "\n${COLOR_BLUE}[4/5] Richte Polkit- & Sudoers-Berechtigungen ein...${COLOR_RESET}"
if [ "$INSTALL_USER" = false ]; then
    if [ -d "/etc/polkit-1/rules.d" ] && [ -f "$SOURCE_DIR/resources/49-cachy-security-suite.rules" ]; then
        cp "$SOURCE_DIR/resources/49-cachy-security-suite.rules" "/etc/polkit-1/rules.d/49-cachy-security-suite.rules"
        chmod 644 "/etc/polkit-1/rules.d/49-cachy-security-suite.rules"
        chown root:root "/etc/polkit-1/rules.d/49-cachy-security-suite.rules" 2>/dev/null || true
        echo -e "${COLOR_GREEN}✓ Polkit-Regel nach /etc/polkit-1/rules.d/ installiert.${COLOR_RESET}"
    fi
    if [ -d "/etc/sudoers.d" ] && [ -f "$SOURCE_DIR/resources/cachy-security-suite.sudoers" ]; then
        cp "$SOURCE_DIR/resources/cachy-security-suite.sudoers" "/etc/sudoers.d/99-cachy-security-suite"
        chmod 440 "/etc/sudoers.d/99-cachy-security-suite"
        chown root:root "/etc/sudoers.d/99-cachy-security-suite" 2>/dev/null || true
        echo -e "${COLOR_GREEN}✓ Sudoers-Drop-in nach /etc/sudoers.d/ installiert.${COLOR_RESET}"
    fi
    mkdir -p "/etc/cachy-security-suite" 2>/dev/null || true
    touch "/etc/cachy-security-suite/polkit-configured" 2>/dev/null || true
    chmod 755 "/etc/cachy-security-suite" 2>/dev/null || true
    chmod 644 "/etc/cachy-security-suite/polkit-configured" 2>/dev/null || true
else
    # User-Mode: check if configured or run setup
    if [ "$NO_POLKIT" = true ]; then
        echo "Polkit-Einrichtung übersprungen (--no-polkit)."
    elif [ "$WITH_POLKIT" = true ] || [ -f "/etc/cachy-security-suite/polkit-configured" ]; then
        echo ">> Aktualisiere Polkit- & Sudoers-Regeln..."
        bash "$SOURCE_DIR/setup-polkit.sh" || echo "Hinweis: Polkit-Einrichtung übersprungen."
    elif [ -t 0 ]; then
        echo -e "${COLOR_YELLOW}Möchtest du Polkit- & Sudoers-Regeln für passwortlose Aktionen (UFW, ClamAV) einrichten? [J/n]${COLOR_RESET} "
        read -rp "> " POLKIT_ANSWER
        if [[ ! "$POLKIT_ANSWER" =~ ^[Nn] ]]; then
            bash "$SOURCE_DIR/setup-polkit.sh" || echo "Hinweis: Polkit-Einrichtung übersprungen."
        fi
    else
        echo "Hinweis: Polkit-Regeln können im Menü Werkzeuge -> 'Passwortlose Aktionen konfigurieren' eingerichtet werden."
    fi
fi

# Create Desktop entry
cat <<EOF > "$APP_DIR/cachy-security-suite.desktop"
[Desktop Entry]
Name=Cachy Security Suite
Comment=Security and audit suite for Arch Linux & CachyOS
GenericName=Security Suite
Exec=$BIN_DIR/cachy-security-suite
Icon=aur-scanner
Terminal=false
Type=Application
Categories=System;Security;Utility;
Keywords=cachy;cachyos;security;scanner;aur;clamav;antivirus;arch;pkgbuild;pacman;
StartupNotify=true
StartupWMClass=cachy-security-suite
EOF

# Compatibility desktop entry
cp "$APP_DIR/cachy-security-suite.desktop" "$APP_DIR/aur-scanner-gui.desktop" 2>/dev/null || true

# 5. Updating caches
echo -e "\n${COLOR_BLUE}[5/5] Aktualisiere System-Caches...${COLOR_RESET}"
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true
fi

echo -e "\n${COLOR_GREEN}====================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}✓ Installation erfolgreich abgeschlossen!${COLOR_RESET}"
echo -e "${COLOR_GREEN}====================================================${COLOR_RESET}\n"
echo -e "Du kannst die Anwendung jetzt wie folgt starten:"
echo -e "  1. Im Anwendungsmenü (Kickoff/KRunner): Suche nach ${COLOR_BLUE}Cachy Security Suite${COLOR_RESET}"
echo -e "  2. Im Terminal: ${COLOR_GREEN}cachy-security-suite${COLOR_RESET} (oder ${COLOR_GREEN}aur-scanner-gui${COLOR_RESET})"
if [ "$INSTALL_USER" = true ]; then
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo -e "\n${COLOR_YELLOW}Hinweis:${COLOR_RESET} '$HOME/.local/bin' ist noch nicht in deinem \$PATH enthalten."
        echo -e "Füge folgende Zeile zu deiner ~/.bashrc oder ~/.zshrc hinzu:"
        echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi
echo ""
