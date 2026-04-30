"""Scan result model containing all analysis results."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Framework, Severity
from apiposture.core.models.finding import Finding


@dataclass
class ScanResult:
    """Result of a security scan."""

    # Path that was scanned
    scan_path: Path

    # All discovered endpoints
    endpoints: list[Endpoint] = field(default_factory=list)

    # All security findings
    findings: list[Finding] = field(default_factory=list)

    # Files that were scanned
    files_scanned: list[Path] = field(default_factory=list)

    # Files that had parse errors
    parse_errors: dict[Path, str] = field(default_factory=dict)

    # Frameworks detected
    frameworks_detected: set[Framework] = field(default_factory=set)

    # Scan start time
    start_time: datetime = field(default_factory=datetime.now)

    # Scan end time
    end_time: datetime | None = None

    @property
    def duration_ms(self) -> int:
        """Get scan duration in milliseconds."""
        if self.end_time is None:
            return 0
        delta = self.end_time - self.start_time
        return int(delta.total_seconds() * 1000)

    @property
    def active_findings(self) -> list[Finding]:
        """Get findings that are not suppressed."""
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed_findings(self) -> list[Finding]:
        """Get findings that are suppressed."""
        return [f for f in self.findings if f.suppressed]

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get active findings of a specific severity."""
        return [f for f in self.active_findings if f.severity == severity]

    def findings_at_or_above(self, severity: Severity) -> list[Finding]:
        """Get active findings at or above a severity level."""
        return [f for f in self.active_findings if f.severity >= severity]

    @property
    def has_critical(self) -> bool:
        """Check if there are any critical findings."""
        return any(f.severity == Severity.CRITICAL for f in self.active_findings)

    @property
    def has_high(self) -> bool:
        """Check if there are any high or critical findings."""
        return any(f.severity >= Severity.HIGH for f in self.active_findings)

    @property
    def severity_summary(self) -> dict[Severity, int]:
        """Get a summary of findings by severity."""
        summary: dict[Severity, int] = {s: 0 for s in Severity}
        for finding in self.active_findings:
            summary[finding.severity] += 1
        return summary

    def to_dict(self) -> dict[str, object]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "scan_path": str(self.scan_path),
            "files_scanned": len(self.files_scanned),
            "parse_errors": len(self.parse_errors),
            "frameworks_detected": [f.value for f in self.frameworks_detected],
            "duration_ms": self.duration_ms,
            "summary": {
                "total_endpoints": len(self.endpoints),
                "total_findings": len(self.active_findings),
                "suppressed_findings": len(self.suppressed_findings),
                "severity_counts": {s.value: c for s, c in self.severity_summary.items()},
            },
            "endpoints": [
                {
                    "route": e.full_route,
                    "methods": [m.value for m in e.methods],
                    "file_path": str(e.file_path),
                    "line_number": e.line_number,
                    "framework": e.framework.value,
                    "classification": e.classification.value,
                    "function_name": e.function_name,
                    "class_name": e.class_name,
                }
                for e in self.endpoints
            ],
            "findings": [f.to_dict() for f in self.findings],
        }
