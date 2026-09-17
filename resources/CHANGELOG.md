# Cachy Security Suite - Changelog

Alle wichtigen Änderungen und Neuerungen an der Cachy Security Suite werden in dieser Datei dokumentiert.

## [1.3.0] - 2026-09-17

### 🛠️ Nahtlose Setup- & Update-Integration für Polkit-Regeln
- **Integration in den Installer (`install.sh`):**
  - Polkit- & Sudoers-Regeln sind jetzt fest als Schritt `[4/5]` im Setup verankert.
  - Bei Neuinstallation oder Update wird geprüft, ob die Regeln bereits aktiv sind: Vorhandene Regeln werden automatisch auf den neuesten Stand gebracht.
  - Im interaktiven Modus wird der Benutzer gefragt, ob er die passwortlosen Regeln direkt einrichten möchte (`[J/n]`).
  - Neue CLI-Flags für den Installer: `--with-polkit` zur automatisierten Einrichtung und `--no-polkit` zum Überspringen.
- **Integration in das Sicherheits- & Update-Center (`updater.py`):**
  - Neue Statuskarte **„System-Rechte & Polkit-Regeln“** im Update-Center.
  - Live-Erkennung des Status: `✓ Aktiv` (wenn konfiguriert) bzw. `⚠️ Nicht eingerichtet` (inkl. Empfehlung zur Einrichtung).
  - Direkter Absprungpunkt: Ein Klick auf „Jetzt einrichten“ bzw. „Verwalten / Update“ öffnet den Konfigurationsdialog und aktualisiert die Ansicht sofort im Anschluss.
  - Schnelle unprivilegierte Zustandserkennung über System-Marker `/etc/cachy-security-suite/polkit-configured`.

---

## [1.2.9] - 2026-09-17

### 🔑 Passwortlose Aktionen via Polkit & Sudoers Profile
- **Optionale Freigabe administrativer Aktionen:**
  - Neue komfortable Einrichtungsfunktion für Benutzer der Administrator-Gruppe `wheel` (Standard unter CachyOS und Arch Linux).
  - Sicherheitsrelevante Kernfunktionen können künftig ohne ständige Passwortabfragen ausgeführt werden:
    - **UFW Firewall:** Ein- und Ausschalten, Profile anwenden, Standard-Richtlinien und Firewall-Regeln verwalten.
    - **ClamAV Freshclam Service:** Hintergrunddienst starten, stoppen, aktivieren oder deaktivieren.
    - **Freshclam Signaturen:** Manuelles und automatisiertes Herunterladen aktueller Virensignaturen.
- **Grafischer Einrichtungsdialog (PolkitSetupDialog):**
  - Erreichbar im Hauptmenü über **Werkzeuge ➔ Passwortlose Aktionen konfigurieren (Polkit)...**.
  - Bietet Ein-Klick-Aktivierung („Jetzt einrichten“) sowie vollständige Rückgängigmachung („Regeln entfernen“) mit detaillierter Konsolen- und Statusausgabe.
- **Systemdateien & Vorlagen:**
  - Polkit-Regel `/etc/polkit-1/rules.d/49-cachy-security-suite.rules` (bzw. `/usr/share/polkit-1/rules.d/`).
  - Sudoers-Drop-in `/etc/sudoers.d/99-cachy-security-suite` mit automatischer `visudo`-Validierung.
  - Automatisches Bereitstellen bei systemweiter Installation (`install.sh` & `PKGBUILD`).

---

## [1.2.8] - 2026-09-17

### 🎚️ Schiebeschalter für den Freshclam-Hintergrunddienst
- **Eleganter Schiebeschalter (Toggle Switch):**
  - **Virenscanner & Update-Center:** Der bisherige Aktions-Button für den Hintergrunddienst wurde sowohl im Virenscanner-Banner als auch im Update-Center-Dialog („Nach Updates suchen...“) durch einen modernen, interaktiven Schiebeschalter (`ToggleSwitch`) mit sanfter Übergangsanimation ersetzt.
  - **Live-Statusanzeige:** Direkte Kennzeichnung des Dienstzustands (`Dienst: Aktiv` in Smaragdgrün bzw. `Dienst: Inaktiv` in Schiefergrau).
  - **Sichere Bedienung:**
    - Beim Einschalten: Bestätigungsdialog bzw. Aktualisierungsschritt zur Aktivierung und polkit-autorisierter Start (`pkexec systemctl enable --now clamav-freshclam.service`).
    - Beim Ausschalten: Bestätigungsdialog zum Stoppen und dauerhaften Entfernen aus dem Autostart (`pkexec systemctl disable --now clamav-freshclam.service`).
    - Bricht der Benutzer den Bestätigungsdialog ab oder schlägt der Vorgang fehl, federt der Schalter automatisch verzögerungsfrei auf den tatsächlichen Systemd-Zustand zurück.

---

## [1.2.7] - 2026-09-16

### 🐛 Bugfixing & Stabilitätsverbesserungen
- **Virenscanner Status- und Abbruchbehandlung:**
  - Behebung einer Race-Condition im Antivirus-Modul: Wenn ein ClamAV-Scan durch den Benutzer vorzeitig abgebrochen wird, bleibt der Status auf „Abgebrochen“ erhalten und wird nicht mehr fälschlicherweise durch den Beendigungs-Handler auf „SAUBER“ überschrieben.
  - Zuverlässiger Abbruch von Hintergrundprozessen: `ClamScanWorker`, `ProcessStreamWorker` und `BatchUpdateWorker` nutzen nun einen sauberen Terminierungsablauf (`terminate()` mit 1 Sekunde Timeout und anschließendem `kill()` Fallback), um verwaiste Prozesse zuverlässig zu beenden.
- **Scanner-Service Fehlerbehandlung:**
  - Vorabinitialisierung von `stdout` und `stderr` in `ScanWorker.run()`, wodurch `UnboundLocalError` bei unerwartetem Ausgang oder ungültiger JSON-Ausgabe verhindert wird.
- **Firewall-Regelverwaltung Fallback:**
  - Robuster Fallback in `FirewallService.delete_rule`: Schlägt das Löschen einer Regel mit angehängtem Kommentar fehl, wird automatisch ein erneuter Löschversuch ohne Kommentarparameter ausgeführt, um Formatierungsunterschiede in UFW auszugleichen.
- **CLI & Updater Parameterharmonisierung:**
  - Ergänzung des Parameters `--token` im CLI-Einstiegspunkt `main.py` bei Aufruf mit `--download-and-install`, um konsistentes Verhalten mit dem Standalone-Updater zu gewährleisten.
  - Dynamischer `User-Agent` (`Cachy-Security-Suite/<version>`) in `AurDownloadDialog`.
  - Vollständiger Schutz vor unbeabsichtigten Secret-Exposures bei Repository-Synchronisationen.

---

## [1.2.5] - 2026-09-16

### 🛡️ System-Scan & Dienst-Management für den Virenscanner (ClamAV)
- **Erweiterter System-Scan für ClamAV:**
  - Neues **„System-Scan ▾“** Menü mit optimierten Voreinstellungen:
    - ⚡ **Schneller System-Scan:** Prüft kritische Ausführungspfade (`/home`, `/etc`, `/usr/bin`, `/usr/local/bin`, `/opt`).
    - 🛡️ **Vollständiger System-Scan:** Durchsucht das gesamte Dateisystem (`/`).
    - 🏠 **Benutzer-Verzeichnis:** Schneller Scan des aktuellen Home-Ordners (`~/`).
    - 📥 **Downloads-Ordner:** Gezielte Überprüfung frisch heruntergeladener Dateien.
  - **Sichere Filesystem-Exclusionen:**
    - Automatische Ausnahme virtueller und flüchtiger Systempfade (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/mnt`, `/media`, `/run/media`, Docker/Flatpak), wodurch Hänger und Endlosschleifen bei Scans auf `/` zuverlässig verhindert werden.
  - **Checkbox „Nur Funde (-i)“:**
    - Optionale Filterung zur Protokollierung nur tatsächlich infizierter oder verdächtiger Dateien – schont Ressourcen und hält das Log auch bei Hunderttausenden gescannten Dateien übersichtlich.

### 🗑️ Freshclam Hintergrunddienst-Verwaltung & Löschen
- **1-Klick-Steuerung für `clamav-freshclam.service`:**
  - Neuer Button im Virenscanner-Banner und im Update-Center:
    - Wenn aktiv/aktiviert: **„🗑️ Freshclam-Dienst löschen“** – beendet den Daemon sofort und entfernt ihn dauerhaft aus dem systemd-Systemstart (`pkexec systemctl disable --now clamav-freshclam.service`).
    - Wenn inaktiv: **„⚙️ Freshclam-Dienst aktivieren“** – startet und aktiviert automatische Signatur-Updates.
  - Dynamischer Statusabgleich mit Systemd in Echtzeit.

### 🚀 Release-Management
- Unterstützung des Schalters `--no-install` im Veröffentlichungsskript `release.sh` zur Bereitstellung und Veröffentlichung auf GitHub ohne automatische lokale Überschreibung.

---

## [1.2.0] - 2026-09-15

### 🛡️ Integrierte Firewall-Steuerung & Netzwerkschutz
- **Vollständige Linux-Paketfilter-Steuerung (UFW / Netfilter):**
  - **Zustands- & Engine-Banner:** Visuelle Statusanzeige (🟢 Aktiv & Geschützt / 🔴 Deaktiviert) mit 1-Klick-Toggle-Button.
  - **Passives Lesen ohne Root:** Status, Standard-Richtlinien (DROP / ACCEPT) und bestehende Regeln werden blitzschnell und ohne Passwortabfrage aus `/etc/ufw/` ausgelesen.
  - **Sicherheitsprofile mit 1 Klick:**
    - 🏠 *Heimnetzwerk (Standard):* Eingehend blockieren (DROP), Ausgehend erlauben (ACCEPT).
    - ☕ *Öffentliches WLAN (Strikt):* Eingehend blockieren, Ausgehend erlauben, striktes Logging.
    - 🔒 *Sicherheits-Lockdown:* Notfall-Modus zur vollständigen Netzwerk-Isolierung.
- **Interaktive Regel-Verwaltung:**
  - Übersichtliche Tabelle aller aktiven Portfreigaben und Sperren (Aktion, Richtung, Port, Protokoll, Quelle, IPv4/IPv6, Kommentar).
  - **Neuer Regel-Dialog (`AddRuleDialog`):**
    - Vordefinierte Vorlagen für gängige Dienste (SSH, KDE Connect, Web HTTP/HTTPS, Samba, Steam/Gaming, WireGuard VPN, LocalSend, DNS).
    - Freie Konfiguration von Portbereichen, Protokollen (TCP, UDP, ANY), Richtung (In/Out) und Quell-IPs.
  - **1-Klick-Löschen:** Selektierte Firewall-Regeln bequem mit Sicherheitsabfrage entfernen.
- **Echtzeit-Blockprotokoll:**
  - Live-Anzeige der letzten vom Paketfilter abgewiesenen Verbindungsversuche (`[UFW BLOCK]`) direkt aus dem System-Journal.
- **Integration:**
  - Neuer Menüpunkt **„Firewall“** in der linken Sidebar der Cachy Security Suite.
  - Dynamischer Versions-Badge `SUITE v1.2.0` in der Kopfleiste.

---

## [1.1.5] - 2026-09-15

### 🎨 GUI Modernisierung & Feinschliff
- **Komplett überarbeitetes Dark-Slate Design:**
  - Modernes, augenschonendes Farbschema mit tiefem Dunkelblau-Grau (`#0b0f19` / `#111827`) und eleganten Akzenten.
  - Abgerundete Card-Layouts, dezente Umrandungen (`#1e293b`) und weiche Übergänge passend zu modernen Linux-Desktops (CachyOS / KDE / GNOME).
- **Verfeinerte Sidebar & Navigation:**
  - Glühender Logo-Badge-Container mit dezentem Neon-Glow (`#38bdf8`).
  - Vertikaler Akzentstreifen für aktive Tabs, sanfte Hover-Effekte und stylischer Version-Badge `SUITE v1.1.5`.
  - Kompakter Systemstatus-Footer mit Live-Status-Dot.
- **Moderne Metrik-Karten & Statusanzeigen:**
  - Farbcodierte Indikatoren für Warnungen, Funde und saubere Prüfungen mit Farbverläufen (`#172033` → `#0e1626`).
- **Überarbeitete Ansichten & Steuerelemente:**
  - System-Scan, Antivirus (ClamAV), Vorabprüfung und Lokaler Scan mit einheitlichen Schnellaktions-Buttons, modernen Eingabefeldern und schicken Tabellen/Log-Bereichen.
  - Schlanke, elegante 8px-Scrollbars im gesamten Anwendungsbereich.

### 🔄 GitHub-Updater & Deployment
- Direkte Anbindung an das offizielle Repository `lenzi96/cachy-security-suite`.
- Synchronisation aller Build- und Installations-Skripte auf Version 1.1.5.

---

## [1.1.0] - 2026-09-15

### 🚀 Highlights & Neue Funktionen
- **Zentrales Sicherheits- & Update-Center:**
  - Modernes Dashboard mit 4-Komponenten-Status: GUI, Core CLI Engine, ClamAV-Virensignaturen und IOC-Bedrohungsdatenbank.
  - **1-Klick „Alle aktualisieren“-Queue:** Führt automatisch alle ausstehenden Sicherheitsupdates nacheinander aus.
- **Dezenter Hintergrund-Check:**
  - Automatische, leise Prüfung auf neue Versionen und veraltete Signaturen beim Programmstart.
  - Sanfter Benachrichtigungs-Indikator in der Sidebar ohne störende Popups.
- **ClamAV Daemon & Automatisierungs-Verwaltung:**
  - Statusanzeige des Hintergrunddienstes `clamav-freshclam.service`.
  - 1-Klick-Aktivierung des Systemd-Dienstes für vollautomatische Signatur-Updates.
- **Integrierter Release-Notes & Changelog-Viewer:**
  - Neuer Reiter im Update-Center zur direkten Einsicht aller Änderungen vor der Aktualisierung.
- **Intelligenter Self-Updater:**
  - Verbesserte Reinstallation mit anschließendem direktem App-Neustart-Prompt.

---

## [1.0.0] - 2026-09-14

### 🛡️ Rebranding & Kernfunktionen
- **Rebranding zur Cachy Security Suite:**
  - Vollständige Überarbeitung des Designs, neuer moderner Sidebar-Look und Icons.
  - Neuer Anwendungsstarter `cachy-security-suite` mit vollständiger Abwärtskompatibilität zu `aur-scanner-gui`.
- **Integrierter Virenscanner & Malware-Schutz:**
  - ClamAV-Integration für System- und Pfad-Scans mit Heuristik.
  - Native Polkit-Berechtigungseskalation für `freshclam`-Signaturupdates.
- **AUR Vorab-Prüfung & Snapshot-Downloader:**
  - Direkte Sicherheitsprüfung vor der Installation von AUR-Paketen.
  - Integrierter Download von Tarball-Snapshots und Git-Clones mit Verknüpfung zu Virenscanner und PKGBUILD-Analyse.
- **System-Audit & Sicherheitsregeln:**
  - Prüfung aller installierten Fremdpakete gegen 118 Sicherheitsregeln und Verhaltensheuristiken.
- **Grafischer Installer:**
  - Assistentengestützte Installation (`cachy-security-suite-installer`).
