"""Terminal output formatter using Rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apiposture.core.models.enums import SecurityClassification, Severity
from apiposture.core.models.scan_result import ScanResult
from apiposture.output.base import FormatterOptions, OutputFormatter

# Severity icons (emoji) and text fallbacks for icon-disabled mode
SEVERITY_ICONS = {
    Severity.CRITICAL: "\u274c",       # Red X
    Severity.HIGH: "\u26a0\ufe0f",    # Warning sign
    Severity.MEDIUM: "\u26a1",         # Lightning bolt
    Severity.LOW: "\u2139\ufe0f",     # Info
    Severity.INFO: "\u2139\ufe0f",    # Info
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
}

SEVERITY_RICH_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# Severity colors and icons (kept for classification table)
SEVERITY_STYLES = {
    Severity.CRITICAL: ("bold red", SEVERITY_ICONS[Severity.CRITICAL]),
    Severity.HIGH: ("red", SEVERITY_ICONS[Severity.HIGH]),
    Severity.MEDIUM: ("yellow", SEVERITY_ICONS[Severity.MEDIUM]),
    Severity.LOW: ("blue", SEVERITY_ICONS[Severity.LOW]),
    Severity.INFO: ("dim", SEVERITY_ICONS[Severity.INFO]),
}

# Classification colors
CLASSIFICATION_STYLES = {
    SecurityClassification.PUBLIC: "red",
    SecurityClassification.AUTHENTICATED: "green",
    SecurityClassification.ROLE_RESTRICTED: "cyan",
    SecurityClassification.POLICY_RESTRICTED: "magenta",
}


class TerminalFormatter(OutputFormatter):
    """Terminal output formatter using Rich."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        super().__init__(options)

    def format(self, result: ScanResult) -> str:
        """Format for string output (minimal)."""
        lines = [
            f"Scanned: {result.scan_path}",
            f"Files: {len(result.files_scanned)}",
            f"Endpoints: {len(result.endpoints)}",
            f"Findings: {len(result.active_findings)}",
        ]
        return "\n".join(lines)

    def print(self, result: ScanResult, console: Console) -> None:
        """Print formatted output using Rich."""
        # Header
        self._print_header(result, console)

        # Summary
        self._print_summary(result, console)

        # Findings
        if result.active_findings:
            self._print_findings(result, console)

        # Endpoints table
        if result.endpoints:
            self._print_endpoints(result, console)

        # Footer
        self._print_footer(result, console)

    def _print_header(self, result: ScanResult, console: Console) -> None:
        """Print the header panel."""
        header_text = Text()
        header_text.append("ApiPosture Security Scan\n", style="bold")
        header_text.append(f"Path: {result.scan_path}", style="dim")

        console.print(Panel(header_text, border_style="blue"))
        console.print()

    def _print_summary(self, result: ScanResult, console: Console) -> None:
        """Print the summary panel."""
        summary = result.severity_summary

        # Create summary text
        summary_parts = []

        if summary[Severity.CRITICAL] > 0:
            summary_parts.append(f"[bold red]{summary[Severity.CRITICAL]} critical[/]")
        if summary[Severity.HIGH] > 0:
            summary_parts.append(f"[red]{summary[Severity.HIGH]} high[/]")
        if summary[Severity.MEDIUM] > 0:
            summary_parts.append(f"[yellow]{summary[Severity.MEDIUM]} medium[/]")
        if summary[Severity.LOW] > 0:
            summary_parts.append(f"[blue]{summary[Severity.LOW]} low[/]")
        if summary[Severity.INFO] > 0:
            summary_parts.append(f"[dim]{summary[Severity.INFO]} info[/]")

        findings_str = ", ".join(summary_parts) if summary_parts else "[green]No findings[/]"

        # Frameworks detected
        frameworks = ", ".join(f.value for f in result.frameworks_detected) or "None"

        console.print(f"[bold]Files scanned:[/] {len(result.files_scanned)}")
        console.print(f"[bold]Frameworks:[/] {frameworks}")
        console.print(f"[bold]Endpoints:[/] {len(result.endpoints)}")
        console.print(f"[bold]Findings:[/] {findings_str}")

        if result.parse_errors:
            console.print(f"[yellow]Parse errors:[/] {len(result.parse_errors)}")

        console.print()

    def _print_findings(self, result: ScanResult, console: Console) -> None:
        """Print findings table."""
        table = Table(title="Security Findings", show_header=True, header_style="bold")

        table.add_column("Sev", width=4)
        table.add_column("Rule", width=8)
        table.add_column("Route", min_width=20)
        table.add_column("Method", width=8)
        table.add_column("Message", min_width=30)
        table.add_column("Location", width=30)

        for finding in result.active_findings:
            style = SEVERITY_RICH_STYLES[finding.severity]
            icons = SEVERITY_LABELS if self.options.no_icons else SEVERITY_ICONS
            sev_text = icons[finding.severity]

            table.add_row(
                Text(sev_text, style=style),
                finding.rule_id,
                finding.endpoint.full_route,
                finding.endpoint.display_methods,
                finding.message,
                finding.location,
            )

        console.print(table)
        console.print()

    def _print_endpoints(self, result: ScanResult, console: Console) -> None:
        """Print endpoints table."""
        table = Table(title="Discovered Endpoints", show_header=True, header_style="bold")

        table.add_column("Route", min_width=25)
        table.add_column("Method", width=10)
        table.add_column("Classification", width=15)
        table.add_column("Framework", width=12)
        table.add_column("Function", width=20)
        table.add_column("Location", width=30)

        for endpoint in result.endpoints:
            class_style = CLASSIFICATION_STYLES.get(endpoint.classification, "")

            table.add_row(
                endpoint.full_route,
                endpoint.display_methods,
                Text(endpoint.classification.value, style=class_style),
                endpoint.framework.value,
                endpoint.function_name,
                endpoint.location,
            )

        console.print(table)
        console.print()

    def _print_footer(self, result: ScanResult, console: Console) -> None:
        """Print footer with timing."""
        console.print(f"[dim]Scan completed in {result.duration_ms}ms[/]")
