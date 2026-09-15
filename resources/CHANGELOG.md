# Cachy Security Suite - Changelog

Alle wichtigen Änderungen und Neuerungen an der Cachy Security Suite werden in dieser Datei dokumentiert.

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
