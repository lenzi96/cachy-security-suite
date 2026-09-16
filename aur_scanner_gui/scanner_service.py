"""
Backend service and worker threads for interacting with aur-scan CLI.
"""
import json
import os
import re
import subprocess
from typing import List, Optional, Tuple

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from aur_scanner_gui.models import Finding, FindingLocation, RuleItem, ScanResult


class ScanWorker(QThread):
    finished = pyqtSignal(ScanResult)
    error = pyqtSignal(str)

    def __init__(self, target_path: str, severity: Optional[str] = None):
        super().__init__()
        self.target_path = target_path
        self.severity = severity
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        stdout = ""
        stderr = ""
        try:
            cmd = ["aur-scan", "scan", "-f", "json", "-q"]
            if self.severity:
                cmd.extend(["-s", self.severity.lower()])
            cmd.append(self.target_path)

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            if self._is_cancelled:
                return

            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()

            if not stdout and stderr:
                self.error.emit(f"Scan-Fehler: {stderr}")
                return

            # Sometimes CLI outputs summary after json if -q is bypassed or warnings occur
            # Extract valid JSON block
            json_str = stdout
            if not json_str.startswith("{"):
                start_idx = stdout.find("{")
                end_idx = stdout.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    json_str = stdout[start_idx : end_idx + 1]

            data = json.loads(json_str)

            findings_list: List[Finding] = []
            for item in data.get("findings", []):
                loc_data = item.get("location") or {}
                loc = FindingLocation(
                    file=loc_data.get("file", ""),
                    line=loc_data.get("line"),
                    column=loc_data.get("column"),
                    snippet=loc_data.get("snippet", ""),
                )
                finding = Finding(
                    id=item.get("id", "UNKNOWN"),
                    severity=item.get("severity", "info"),
                    category=item.get("category", "General"),
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    location=loc,
                    recommendation=item.get("recommendation", ""),
                    cwe_id=item.get("cwe_id"),
                    metadata=item.get("metadata", {}),
                )
                findings_list.append(finding)

            result = ScanResult(
                package_name=data.get("package_name", os.path.basename(self.target_path)),
                package_version=data.get("package_version", ""),
                scan_duration_ms=data.get("scan_duration_ms", 0),
                timestamp=data.get("timestamp", ""),
                scanned_files=data.get("scanned_files", []),
                findings=findings_list,
                raw_output=stdout,
            )
            self.finished.emit(result)

        except json.JSONDecodeError as exc:
            self.error.emit(f"JSON-Verarbeitungsfehler: {exc}\nAusgabe:\n{stdout}")
        except Exception as exc:
            self.error.emit(f"Unerwarteter Fehler: {exc}")


class ProcessStreamWorker(QThread):
    output_line = pyqtSignal(str)
    completed = pyqtSignal(int, str)  # returncode, full_output
    error = pyqtSignal(str)

    def __init__(self, command: List[str]):
        super().__init__()
        self.command = command
        self.process: Optional[subprocess.Popen] = None
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=1)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

    def run(self):
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            full_output = []
            if self.process.stdout:
                for line in iter(self.process.stdout.readline, ""):
                    if self._is_cancelled:
                        break
                    line_clean = line.rstrip()
                    full_output.append(line_clean)
                    self.output_line.emit(line_clean)

            self.process.wait()
            ret_code = self.process.returncode if self.process else 0
            if not self._is_cancelled:
                self.completed.emit(ret_code, "\n".join(full_output))
        except Exception as exc:
            self.error.emit(str(exc))


class AurScannerService(QObject):
    @staticmethod
    def get_rules() -> List[RuleItem]:
        """Runs aur-scan codes and returns parsed list of rules."""
        try:
            proc = subprocess.run(
                ["aur-scan", "codes"],
                capture_output=True,
                text=True,
                check=False,
            )
            category = "General"
            rules: List[RuleItem] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if (
                    not line
                    or line.startswith("AUR Security")
                    or line.startswith("===")
                    or "codes across" in line
                    or line.startswith("Use ")
                    or line.startswith("Add your")
                ):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    category = line[1:-1]
                    continue
                m = re.match(r"^([A-Z0-9_\-]+)\s+\[([^\]]+)\]\s+(.*)$", line)
                if m:
                    rules.append(
                        RuleItem(
                            id=m.group(1),
                            severity=m.group(2),
                            title=m.group(3),
                            category=category,
                        )
                    )
            return rules
        except Exception:
            return []

    @staticmethod
    def explain_code(code: str) -> str:
        """Runs aur-scan explain <code> and returns formatted description."""
        try:
            proc = subprocess.run(
                ["aur-scan", "explain", code],
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.stdout.strip()
        except Exception as exc:
            return f"Fehler beim Laden der Erklärung: {exc}"

    @staticmethod
    def get_ioc_summary() -> str:
        """Runs aur-scan ioc and returns summary text."""
        try:
            proc = subprocess.run(
                ["aur-scan", "ioc"],
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.stdout.strip()
        except Exception as exc:
            return f"Fehler beim Laden der IOC-Datenbank: {exc}"

    @staticmethod
    def check_ioc_indicator(name: str) -> str:
        """Runs aur-scan ioc --check <name>."""
        try:
            proc = subprocess.run(
                ["aur-scan", "ioc", "--check", name],
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.stdout.strip() or "Kein Treffer in der IOC-Datenbank gefunden."
        except Exception as exc:
            return f"Fehler bei IOC-Prüfung: {exc}"

    @staticmethod
    def get_version_info() -> str:
        """Runs aur-scan version."""
        try:
            proc = subprocess.run(
                ["aur-scan", "version"],
                capture_output=True,
                text=True,
                check=False,
            )
            return proc.stdout.strip()
        except Exception as exc:
            return f"Fehler: {exc}"
