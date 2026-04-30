"""Main CLI application using Typer."""

import typer
from rich.console import Console

from apiposture import __version__
from apiposture.cli.license import license_app
from apiposture.cli.scan import scan

console = Console()

app = typer.Typer(
    name="apiposture",
    help="Security inspection tool for Python API frameworks",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register subcommands
app.command()(scan)
app.add_typer(license_app, name="license", help="License management commands")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        is_eager=True,
    ),
) -> None:
    """ApiPosture - Security inspection tool for Python API frameworks."""
    if version:
        console.print(f"apiposture version {__version__}")
        raise typer.Exit()


if __name__ == "__main__":
    app()
