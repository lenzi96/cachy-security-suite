# Cachy Security Suite - Changelog

Alle wichtigen Änderungen und Neuerungen an der Cachy Security Suite werden in dieser Datei dokumentiert.

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
