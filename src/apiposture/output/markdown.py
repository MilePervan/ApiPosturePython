"""Markdown output formatter."""

from apiposture.core.models.enums import Severity
from apiposture.core.models.scan_result import ScanResult
from apiposture.output.base import FormatterOptions, OutputFormatter


class MarkdownFormatter(OutputFormatter):
    """Markdown output formatter."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        super().__init__(options)

    def format(self, result: ScanResult) -> str:
        """Format the scan result as Markdown."""
        lines: list[str] = []

        # Header
        lines.append("# ApiPosture Security Scan Report")
        lines.append("")
        lines.append(f"**Scan Path:** `{result.scan_path}`")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Files Scanned:** {len(result.files_scanned)}")
        frameworks = ", ".join(f.value for f in result.frameworks_detected) or "None"
        lines.append(f"- **Frameworks Detected:** {frameworks}")
        lines.append(f"- **Endpoints Discovered:** {len(result.endpoints)}")
        lines.append(f"- **Total Findings:** {len(result.active_findings)}")
        lines.append(f"- **Suppressed Findings:** {len(result.suppressed_findings)}")
        lines.append(f"- **Scan Duration:** {result.duration_ms}ms")
        lines.append("")

        # Severity breakdown
        summary = result.severity_summary
        lines.append("### Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        severities = [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
        ]
        for severity in severities:
            count = summary[severity]
            emoji = self._severity_emoji(severity)
            lines.append(f"| {emoji} {severity.value.capitalize()} | {count} |")
        lines.append("")

        # Findings
        if result.active_findings:
            lines.append("## Findings")
            lines.append("")

            for finding in result.active_findings:
                emoji = self._severity_emoji(finding.severity)
                lines.append(f"### {emoji} {finding.rule_id}: {finding.rule_name}")
                lines.append("")
                lines.append(f"**Severity:** {finding.severity.value.capitalize()}")
                lines.append("")
                route = finding.endpoint.full_route
                methods = finding.endpoint.display_methods
                lines.append(f"**Endpoint:** `{route}` [{methods}]")
                lines.append("")
                lines.append(f"**Location:** `{finding.location}`")
                lines.append("")
                lines.append(f"**Message:** {finding.message}")
                lines.append("")
                if finding.recommendation:
                    lines.append(f"**Recommendation:** {finding.recommendation}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # Endpoints
        if result.endpoints:
            lines.append("## Discovered Endpoints")
            lines.append("")
            lines.append("| Route | Methods | Classification | Framework | Function |")
            lines.append("|-------|---------|----------------|-----------|----------|")

            for endpoint in result.endpoints:
                lines.append(
                    f"| `{endpoint.full_route}` | {endpoint.display_methods} | "
                    f"{endpoint.classification.value} | {endpoint.framework.value} | "
                    f"`{endpoint.function_name}` |"
                )
            lines.append("")

        # Parse errors
        if result.parse_errors:
            lines.append("## Parse Errors")
            lines.append("")
            for path, error in result.parse_errors.items():
                lines.append(f"- `{path}`: {error}")
            lines.append("")

        return "\n".join(lines)

    def _severity_emoji(self, severity: Severity) -> str:
        """Get emoji for severity level."""
        if self.options.no_icons:
            return ""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        return emojis.get(severity, "")
