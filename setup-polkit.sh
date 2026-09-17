#!/usr/bin/env bash
# ==============================================================================
# Setup Polkit & Sudoers for Cachy Security Suite
# Enables passwordless execution of UFW and Freshclam actions for 'wheel' group
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Re-run with root privilege if not root
if [ "$EUID" -ne 0 ]; then
    if command -v pkexec &>/dev/null; then
        echo ">> Fordere Berechtigung über pkexec an..."
        exec pkexec bash "$0" "$@"
    elif command -v sudo &>/dev/null; then
        echo ">> Fordere Berechtigung über sudo an..."
        exec sudo bash "$0" "$@"
    else
        echo "FEHLER: Weder pkexec noch sudo gefunden. Bitte als Root ausführen."
        exit 1
    fi
fi

POLKIT_RULES_DIR="/etc/polkit-1/rules.d"
POLKIT_TARGET="$POLKIT_RULES_DIR/49-cachy-security-suite.rules"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_TARGET="$SUDOERS_DIR/99-cachy-security-suite"

if [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
    echo "===================================================="
    echo "  Cachy Security Suite - Berechtigungen entfernen   "
    echo "===================================================="
    REMOVED=0
    if [ -f "$POLKIT_TARGET" ]; then
        rm -f "$POLKIT_TARGET"
        echo "✓ Polkit-Regel entfernt: $POLKIT_TARGET"
        REMOVED=1
    fi
    if [ -f "$SUDOERS_TARGET" ]; then
        rm -f "$SUDOERS_TARGET"
        echo "✓ Sudoers-Drop-in entfernt: $SUDOERS_TARGET"
        REMOVED=1
    fi
    if [ "$REMOVED" -eq 0 ]; then
        echo "Keine installierten Regeln gefunden."
    else
        echo "✓ Alle Berechtigungen wurden erfolgreich entfernt."
    fi
    exit 0
fi

echo "===================================================="
echo "  Cachy Security Suite - Polkit & Sudoers Setup     "
echo "===================================================="

# Locate source rule files
SRC_RULES="$DIR/resources/49-cachy-security-suite.rules"
if [ ! -f "$SRC_RULES" ]; then
    SRC_RULES="/usr/share/cachy-security-suite/resources/49-cachy-security-suite.rules"
fi

SRC_SUDOERS="$DIR/resources/cachy-security-suite.sudoers"
if [ ! -f "$SRC_SUDOERS" ]; then
    SRC_SUDOERS="/usr/share/cachy-security-suite/resources/cachy-security-suite.sudoers"
fi

# 1. Install Polkit Rule
if [ -d "$POLKIT_RULES_DIR" ] && [ -f "$SRC_RULES" ]; then
    echo ">> Installiere Polkit-Regel nach $POLKIT_TARGET..."
    cp "$SRC_RULES" "$POLKIT_TARGET"
    chmod 644 "$POLKIT_TARGET"
    chown root:root "$POLKIT_TARGET" 2>/dev/null || true
    echo "✓ Polkit-Regel erfolgreich installiert."
elif [ ! -d "$POLKIT_RULES_DIR" ]; then
    echo "Hinweis: $POLKIT_RULES_DIR existiert nicht auf diesem System."
elif [ ! -f "$SRC_RULES" ]; then
    echo "WARNUNG: Polkit-Quelldatei nicht gefunden ($SRC_RULES)!"
fi

# 2. Install Sudoers Drop-in
if [ -d "$SUDOERS_DIR" ] && [ -f "$SRC_SUDOERS" ]; then
    echo ">> Installiere Sudoers-Drop-in nach $SUDOERS_TARGET..."
    cp "$SRC_SUDOERS" "$SUDOERS_TARGET"
    chmod 440 "$SUDOERS_TARGET"
    chown root:root "$SUDOERS_TARGET" 2>/dev/null || true

    # Validate syntax with visudo
    if command -v visudo &>/dev/null; then
        if ! visudo -c -f "$SUDOERS_TARGET" >/dev/null 2>&1; then
            echo "WARNUNG: visudo meldet Syntaxfehler! Entferne $SUDOERS_TARGET zur Sicherheit."
            rm -f "$SUDOERS_TARGET"
            exit 1
        fi
    fi
    echo "✓ Sudoers-Drop-in erfolgreich installiert & validiert."
elif [ ! -d "$SUDOERS_DIR" ]; then
    echo "Hinweis: $SUDOERS_DIR existiert nicht auf diesem System."
elif [ ! -f "$SRC_SUDOERS" ]; then
    echo "WARNUNG: Sudoers-Quelldatei nicht gefunden ($SRC_SUDOERS)!"
fi

echo ""
echo "===================================================="
echo "✓ Fertig! Firewall- und Freshclam-Aktionen können"
echo "  künftig ohne Passwortabfrage ausgeführt werden."
echo "===================================================="
