# Cachy Security Suite

Eine moderne, umfassende grafische Sicherheits- und Audit-Zentrale (PyQt6) für Arch Linux & CachyOS. Kombiniert erweitertes AUR-Sicherheits-Audit ([aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner)), PKGBUILD-Codeanalyse, ClamAV-Virenscanner und Datei-Integritätsprüfungen (VirusTotal).

![Cachy Security Suite Logo](resources/aur-scanner-256.png)

## Funktionen

1. **System-Audit (System-Scan - Standard-Startansicht)**
   - Scannt mit einem Klick alle aktuell auf dem System installierten AUR-Pakete (`aur-scan system`).
   - Automatischer Abgleich gegen bekannte IOC-Namen (Indicators of Compromise).
   - Übersichtliche Zähler für installierte Pakete und Sicherheitswarnungen.
   - Option zum Neuladen des AUR-Caches (`--rescan`).

2. **PKGBUILD Scan (Lokaler Scan)**
   - Untersucht lokale `PKGBUILD`-Dateien oder Quellcodeverzeichnisse direkt auf Sicherheitsrisiken.
   - Anzeige strukturierter Befunde mit farbigen Schweregrad-Badges (*Kritisch*, *Hoch*, *Mittel*, *Niedrig*, *Info*).
   - Detailansicht mit Zeilennummer, Kategorie, CWE-Klassifizierung, Handlungsempfehlungen und interaktiver Code-Snippet-Vorschau.
   - Direktsprung zur Dokumentation der auslösenden Erkennungsregel per Klick.

3. **Vorab-Prüfung & AUR-Downloader (Pre-Install Check & Download)**
   - Prüft AUR-Pakete vor der Installation direkt aus dem AUR (`aur-scan check`).
   - Rekursive Analyse des gesamten Abhängigkeitsbaums (AUR- vs. offizielle Repo-Pakete).
   - **Integrierte Download-Funktion (Neu):** Lädt die offiziellen Quellcode-Dateien, `PKGBUILD` und `.SRCINFO` wahlweise als leichtgewichtiges Snapshot-Archiv (`.tar.gz`) oder per `git clone` direkt in den gewünschten Zielordner herunter.
   - **Nahtlose Weiterleitung:** Direkt nach dem Download 1-Klick-Übernahme in den PKGBUILD-Sicherheits-Scan, den ClamAV-Virenscanner oder Anzeige im Dateimanager (Dolphin).
   - Filteroptionen für minimale Schweregrade und optionale Abhängigkeiten.
   - Echtzeit-Streaming der Scan-Ausgabe mit farblicher Hervorhebung.

4. **Integrierter Virenscanner & Malware-Schutz**
   - Dedizierter Viren- und Malware-Scan für Binärdateien, Quellcode-Archive (`.tar.gz`, `.zip`) und Downloads.
   - Nahtlose Integration der Open-Source-Engine **ClamAV** (`clamscan`) inklusive 1-Klick Signatur-Update via `freshclam`.
   - Integrierte Datei-Integritätsprüfung mit automatischer SHA-256 Hashberechnung und Direktabgleich über **VirusTotal Threat Intelligence**.
   - Funktioniert vollständig auch ohne ClamAV über Datei-Integritätsaudits.

5. **Regel-Katalog (Rules & Codes)**
   - Durchsuchbare Bibliothek aller 118 integrierten Sicherheitsregeln über 13 Kategorien (z. B. Command Injection, Credential Theft, Cryptomining, Privilege Escalation, Obfuscation u.v.m.).
   - Vollständige Detailerklärungen, Hintergrundkontexte und Beispiele (`aur-scan explain <code>`).

6. **IOC-Datenbank (Bedrohungen)**
   - Übersicht bekannter Schadkampagnen (z. B. Atomic Arch, CHAOS RAT).
   - Interaktive Schnellprüfung von Indikatoren, Paketnamen oder URLs.

## Installation & Weitergabe (Teilen mit anderen)

Das Projekt bietet verschiedene bequeme Methoden zur Installation und Weitergabe:

### 1. Das fertige Release-Archiv weitergeben (Empfohlen für Freunde)
Im Ordner `dist/` liegt ein sofort teilbares Archiv:
```
dist/cachy-security-suite-v1.0.0.tar.gz
```
Ein anderer Nutzer muss dieses Archiv nur entpacken:
```bash
tar -xzf cachy-security-suite-v1.0.0.tar.gz
cd cachy-security-suite-v1.0.0
```

#### A) Grafischer Installations-Assistent (Per Doppelklick oder Befehl):
Einfach die Datei **`setup`** im Dateimanager doppelklicken oder im Terminal starten:
```bash
./setup
# oder
python3 installer.py
```
Ein moderner 4-Schritte-Assistent führt durch die Systemprüfung, Pfadauswahl und richtet alle Icons, Starter und Menü-Einträge automatisch ein!

#### B) Schnelle Terminal-Installation:
```bash
# Entweder ohne Root-Rechte für den eigenen Benutzer:
./install.sh --user

# Oder systemweit für alle Benutzer:
sudo ./install.sh
```

### 2. Als offizielles Arch Linux Paket (PKGBUILD)
Für Arch-Linux- & CachyOS-Puristen ist ein vollständiges `PKGBUILD` enthalten. Bauen und installieren mit:
```bash
makepkg -si
```

### 3. Starten der Anwendung
Nach der Installation kann die Anwendung wie gewohnt gestartet werden:
```bash
cachy-security-suite
# (auch als aur-scanner-gui aufrufbar)
```

### 4. Deinstallation
Mit dem beiliegenden Skript lässt sich die Anwendung sauber wieder entfernen:
```bash
./uninstall.sh --user   # bzw. sudo ./uninstall.sh bei systemweiter Installation
```

## Voraussetzungen
- Arch Linux (oder Derivate wie CachyOS, EndeavourOS, Manjaro)
- `aur-scanner` (`aur-scan` im Pfad, installierbar via `yay -S aur-scanner`)
- Python 3 & `python-pyqt6` (`sudo pacman -S python-pyqt6`)
- *(Optional für Viren-Scans)* `clamav` (`sudo pacman -S clamav`)
