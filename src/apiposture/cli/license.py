"""License management commands (stub for Pro features)."""

import typer
from rich.console import Console

console = Console()

license_app = typer.Typer(
    help="License management commands",
    no_args_is_help=True,
)


@license_app.command()
def activate(
    key: str = typer.Argument(..., help="License key to activate"),
) -> None:
    """Activate a license key."""
    console.print(
        "[yellow]License activation is not available in the open-source version.[/yellow]"
    )
    console.print("Visit https://apiposture.io for Pro features.")


@license_app.command()
def deactivate() -> None:
    """Deactivate the current license."""
    console.print(
        "[yellow]License deactivation is not available "
        "in the open-source version.[/yellow]"
    )


@license_app.command()
def status() -> None:
    """Show license status."""
    console.print("[bold]License Status:[/bold] Community Edition")
    console.print("")
    console.print("Community Edition includes:")
    console.print("  - All 8 security rules")
    console.print("  - FastAPI, Flask, and Django REST Framework support")
    console.print("  - Terminal, JSON, and Markdown output formats")
    console.print("")
    console.print("Visit https://apiposture.io for Pro features.")
