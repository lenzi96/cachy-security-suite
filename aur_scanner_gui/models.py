"""
Data models for aur-scanner GUI
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class FindingLocation:
    file: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: str = ""


@dataclass
class Finding:
    id: str
    severity: str  # critical, high, medium, low, info
    category: str
    title: str
    description: str
    location: FindingLocation = field(default_factory=FindingLocation)
    recommendation: str = ""
    cwe_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_rank(self) -> int:
        ranks = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return ranks.get(self.severity.lower(), 0)

    @property
    def severity_display(self) -> str:
        return self.severity.upper()


@dataclass
class ScanResult:
    package_name: str = ""
    package_version: str = ""
    scan_duration_ms: int = 0
    timestamp: str = ""
    scanned_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "low")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.lower() == "info")

    @property
    def total_count(self) -> int:
        return len(self.findings)

    @property
    def is_safe(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0


@dataclass
class RuleItem:
    id: str
    severity: str
    title: str
    category: str
    explanation: str = ""


@dataclass
class IOCItem:
    title: str
    date: str
    description: str
    url: str = ""
