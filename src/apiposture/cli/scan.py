"""Scan command implementation."""

import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from apiposture.core.models.enums import (
    Framework,
    HttpMethod,
    SecurityClassification,
    Severity,
)

console = Console()


class OutputFormat(str, Enum):
    """Output format options."""

    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"


class SortBy(str, Enum):
    """Sort options for results."""

    SEVERITY = "severity"
    ROUTE = "route"
    METHOD = "method"
    CLASSIFICATION = "classification"


class SortDir(str, Enum):
    """Sort direction."""

    ASC = "asc"
    DESC = "desc"


class GroupBy(str, Enum):
    """Grouping options."""

    FILE = "file"
    CLASSIFICATION = "classification"
    RULE = "rule"
    FRAMEWORK = "framework"


def scan(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to scan (file or directory)",
            exists=True,
            resolve_path=True,
        ),
    ] = Path("."),
    output: Annotated[
        OutputFormat,
        typer.Option("--output", "-o", help="Output format"),
    ] = OutputFormat.TERMINAL,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write output to file"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Configuration file (.apiposture.yaml)"),
    ] = None,
    severity: Annotated[
        Severity,
        typer.Option("--severity", help="Minimum severity to report"),
    ] = Severity.INFO,
    fail_on: Annotated[
        Severity | None,
        typer.Option(
            "--fail-on", help="Exit with code 1 if findings at this severity or above"
        ),
    ] = None,
    sort_by: Annotated[
        SortBy,
        typer.Option("--sort-by", help="Sort results by field"),
    ] = SortBy.SEVERITY,
    sort_dir: Annotated[
        SortDir,
        typer.Option("--sort-dir", help="Sort direction"),
    ] = SortDir.DESC,
    classification: Annotated[
        list[SecurityClassification] | None,
        typer.Option("--classification", help="Filter by security classification"),
    ] = None,
    method: Annotated[
        list[HttpMethod] | None,
        typer.Option("--method", help="Filter by HTTP method"),
    ] = None,
    route_contains: Annotated[
        str | None,
        typer.Option("--route-contains", help="Filter routes containing substring"),
    ] = None,
    framework: Annotated[
        list[Framework] | None,
        typer.Option("--framework", help="Filter by framework"),
    ] = None,
    rule: Annotated[
        list[str] | None,
        typer.Option("--rule", help="Filter by rule ID (e.g., AP001)"),
    ] = None,
    group_by: Annotated[
        GroupBy | None,
        typer.Option("--group-by", help="Group results by field"),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output"),
    ] = False,
    no_icons: Annotated[
        bool,
        typer.Option("--no-icons", help="Disable icons in output"),
    ] = False,
) -> None:
    """Scan a Python project for API security issues."""
    # Import here to avoid circular imports
    from apiposture.core.analysis.project_analyzer import ProjectAnalyzer
    from apiposture.core.configuration.loader import ConfigLoader
    from apiposture.output.base import FormatterOptions, OutputFormatter
    from apiposture.output.json_output import JsonFormatter
    from apiposture.output.markdown import MarkdownFormatter
    from apiposture.output.terminal import TerminalFormatter

    # Load configuration
    config_data = None
    if config and config.exists():
        config_data = ConfigLoader.load(config)
    elif (path / ".apiposture.yaml").exists():
        config_data = ConfigLoader.load(path / ".apiposture.yaml")
    elif (path / ".apiposture.yml").exists():
        config_data = ConfigLoader.load(path / ".apiposture.yml")

    # Run analysis
    analyzer = ProjectAnalyzer(config=config_data)
    result = analyzer.analyze(path)

    # Filter findings by minimum severity
    result.findings = [f for f in result.findings if f.severity >= severity]

    # Filter by classification
    if classification:
        result.endpoints = [
            e for e in result.endpoints if e.classification in classification
        ]
        result.findings = [
            f for f in result.findings if f.endpoint.classification in classification
        ]

    # Filter by method
    if method:
        result.endpoints = [
            e for e in result.endpoints if any(m in method for m in e.methods)
        ]
        result.findings = [
            f for f in result.findings if any(m in method for m in f.endpoint.methods)
        ]

    # Filter by route
    if route_contains:
        result.endpoints = [
            e for e in result.endpoints if route_contains in e.full_route
        ]
        result.findings = [
            f for f in result.findings if route_contains in f.endpoint.full_route
        ]

    # Filter by framework
    if framework:
        result.endpoints = [e for e in result.endpoints if e.framework in framework]
        result.findings = [
            f for f in result.findings if f.endpoint.framework in framework
        ]

    # Filter by rule
    if rule:
        result.findings = [f for f in result.findings if f.rule_id in rule]

    # Sort findings
    reverse = sort_dir == SortDir.DESC
    if sort_by == SortBy.SEVERITY:
        result.findings.sort(key=lambda f: f.severity.order, reverse=reverse)
    elif sort_by == SortBy.ROUTE:
        result.findings.sort(key=lambda f: f.endpoint.full_route, reverse=reverse)
    elif sort_by == SortBy.METHOD:
        result.findings.sort(key=lambda f: f.endpoint.display_methods, reverse=reverse)
    elif sort_by == SortBy.CLASSIFICATION:
        result.findings.sort(
            key=lambda f: f.endpoint.classification.value, reverse=reverse
        )

    # Create formatter options
    options = FormatterOptions(
        no_color=no_color,
        no_icons=no_icons,
        group_by=group_by.value if group_by else None,
    )

    # Select formatter
    formatter: OutputFormatter
    if output == OutputFormat.JSON:
        formatter = JsonFormatter(options)
    elif output == OutputFormat.MARKDOWN:
        formatter = MarkdownFormatter(options)
    else:
        formatter = TerminalFormatter(options)

    # Format output
    output_str = formatter.format(result)

    # Write output
    if output_file:
        output_file.write_text(output_str)
        console.print(f"Output written to {output_file}")
    else:
        if output == OutputFormat.TERMINAL:
            # TerminalFormatter uses rich directly
            formatter.print(result, console)
        else:
            console.print(output_str)

    # Exit with error code if findings at fail_on severity
    if fail_on and result.findings_at_or_above(fail_on):
        sys.exit(1)
